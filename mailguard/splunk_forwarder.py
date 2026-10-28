"""Splunk HTTP Event Collector (HEC) forwarder and local JSONL event persistence module."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple

import requests

from mailguard.models import AnalysisResult
from mailguard.utils import load_config

logger = logging.getLogger(__name__)


class SplunkForwarder:
    """Manages offline-resilient local JSONL logging and remote Splunk HEC ingestion."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        splunk_cfg = self.config.get("splunk", {})
        paths_cfg = self.config.get("paths", {})

        # Local persistence path
        self.output_jsonl_path = Path(paths_cfg.get("output_jsonl", "output/results.jsonl"))

        # Splunk HEC credentials from environment or config
        url_env = splunk_cfg.get("hec_url_env", "SPLUNK_HEC_URL")
        token_env = splunk_cfg.get("hec_token_env", "SPLUNK_HEC_TOKEN")

        self.hec_url = os.environ.get(url_env)
        self.hec_token = os.environ.get(token_env)
        self.index = os.environ.get("SPLUNK_INDEX", splunk_cfg.get("index", "security_lab"))
        self.sourcetype = splunk_cfg.get("sourcetype", "mailguard:analysis")
        
        # Verify SSL flag
        env_verify = os.environ.get("SPLUNK_VERIFY_SSL")
        if env_verify is not None:
            self.verify_ssl = env_verify.lower() in ("true", "1", "yes")
        else:
            self.verify_ssl = bool(splunk_cfg.get("verify_ssl", True))

        self.timeout = float(splunk_cfg.get("timeout_seconds", 5.0))
        self.max_retries = int(splunk_cfg.get("max_retries", 2))

    def persist_locally(self, result: AnalysisResult) -> bool:
        """Always persist analysis record to local JSONL file for offline auditing."""
        try:
            self.output_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            event_data = result.to_dict()
            with open(self.output_jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")
            logger.debug(f"Persisted analysis event locally to {self.output_jsonl_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to persist event to local JSONL ({self.output_jsonl_path}): {e}")
            return False

    def forward_to_splunk(self, result: AnalysisResult) -> Tuple[bool, str]:
        """Send analysis event to Splunk HTTP Event Collector (HEC).
        
        Returns:
            Tuple[bool, str]: (Success boolean, Status message)
        """
        if not self.hec_url or not self.hec_token:
            return False, "Splunk HEC URL or Token not configured in environment (SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN)"

        # Prepare standard Splunk HEC event envelope
        event_dict = result.to_dict()
        epoch_now = int(time.time())
        hec_payload = {
            "time": epoch_now,
            "host": "mailguard-sensor",
            "source": "mailguard",
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event_dict,
        }

        # Authorization header with HEC token (NEVER logged!)
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }

        # Execute POST with retry logic for transient errors
        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self.hec_url,
                    json=hec_payload,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    logger.info(f"Successfully delivered event {result.message_id} to Splunk HEC index={self.index}")
                    return True, "Event successfully delivered to Splunk HEC"
                elif resp.status_code in (401, 403):
                    msg = f"Splunk HEC authentication failed (HTTP {resp.status_code}): Invalid or disabled token"
                    logger.error(msg)
                    return False, msg
                else:
                    last_error = f"HTTP {resp.status_code}: {resp.text}"
                    logger.warning(f"Splunk HEC delivery attempt {attempt} failed: {last_error}")

            except requests.exceptions.SSLError as ssl_err:
                msg = f"Splunk HEC SSL verification error: {ssl_err}"
                logger.error(msg)
                return False, msg
            except requests.exceptions.Timeout:
                last_error = f"Connection timed out after {self.timeout}s"
                logger.warning(f"Splunk HEC attempt {attempt} timed out")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Splunk HEC attempt {attempt} encountered error: {e}")

            time.sleep(0.5 * attempt)

        return False, f"Failed to deliver to Splunk HEC after {self.max_retries} attempts: {last_error}"
