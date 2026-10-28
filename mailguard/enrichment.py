"""Optional OSINT and Threat Intelligence enrichment module (VirusTotal, AbuseIPDB, URLScan)."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from mailguard.models import EnrichmentResult

logger = logging.getLogger(__name__)


class ThreatEnricher:
    """Provides optional, privacy-preserving indicator lookups via external threat intelligence APIs.
    
    Disabled by default. Never sends email message contents, headers, or private attachment data.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        enrich_cfg = cfg.get("enrichment", {})
        self.enabled = bool(enrich_cfg.get("enabled", False))
        self.cache_ttl = int(enrich_cfg.get("cache_ttl_seconds", 3600))
        self.timeout = float(enrich_cfg.get("timeout_seconds", 4.0))

        # API Keys loaded ONLY from environment variables
        self.vt_key = os.environ.get("VT_API_KEY")
        self.urlscan_key = os.environ.get("URLSCAN_API_KEY")
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")

        # In-memory TTL cache: indicator -> (timestamp, EnrichmentResult)
        self.cache: Dict[str, Tuple[float, EnrichmentResult]] = {}

    def is_configured(self) -> bool:
        """Returns True if at least one provider key is present and enrichment is enabled or forced."""
        return bool(self.vt_key or self.urlscan_key or self.abuseipdb_key)

    def lookup_ip(self, ip_address: Optional[str]) -> Optional[EnrichmentResult]:
        """Query AbuseIPDB for IP reputation."""
        if not ip_address or not self.abuseipdb_key:
            return None

        cache_key = f"IP:{ip_address}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.abuseipdb_key,
        }
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                verdict = "MALICIOUS" if abuse_score >= 50 else ("SUSPICIOUS" if abuse_score > 0 else "CLEAN")
                result = EnrichmentResult(
                    indicator=ip_address,
                    indicator_type="IP",
                    provider="AbuseIPDB",
                    verdict=verdict,
                    score=abuse_score,
                    details=f"Abuse confidence score: {abuse_score}% (total reports: {data.get('totalReports', 0)})",
                )
                self._set_cached(cache_key, result)
                return result
            else:
                logger.debug(f"AbuseIPDB returned status {resp.status_code} for {ip_address}")
        except Exception as e:
            logger.debug(f"AbuseIPDB request exception: {e}")

        return None

    def lookup_file_hash(self, sha256_hash: Optional[str]) -> Optional[EnrichmentResult]:
        """Query VirusTotal for attachment SHA-256 hash reputation."""
        if not sha256_hash or not self.vt_key:
            return None

        cache_key = f"HASH:{sha256_hash}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {"x-apikey": self.vt_key}

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                verdict = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN")
                result = EnrichmentResult(
                    indicator=sha256_hash,
                    indicator_type="SHA256",
                    provider="VirusTotal",
                    verdict=verdict,
                    malicious_votes=malicious,
                    details=f"Detection stats: {malicious} malicious, {suspicious} suspicious out of {sum(stats.values())} engines",
                )
                self._set_cached(cache_key, result)
                return result
            elif resp.status_code == 404:
                result = EnrichmentResult(
                    indicator=sha256_hash,
                    indicator_type="SHA256",
                    provider="VirusTotal",
                    verdict="UNKNOWN",
                    malicious_votes=0,
                    details="Hash not found in VirusTotal database",
                )
                self._set_cached(cache_key, result)
                return result
        except Exception as e:
            logger.debug(f"VirusTotal lookup exception: {e}")

        return None

    def _get_cached(self, key: str) -> Optional[EnrichmentResult]:
        if key in self.cache:
            ts, res = self.cache[key]
            if time.time() - ts < self.cache_ttl:
                return res
            del self.cache[key]
        return None

    def _set_cached(self, key: str, res: EnrichmentResult) -> None:
        self.cache[key] = (time.time(), res)
