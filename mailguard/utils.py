"""Utility functions for configuration, domain extraction, IP classification, and sanitization."""

from __future__ import annotations

import html
import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import tldextract
import yaml

logger = logging.getLogger(__name__)

# Initialize an offline-only TLDExtract instance that will not fetch remote public suffix lists
_OFFLINE_TLD_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=False,
    suffix_list_urls=None,
    fallback_to_snapshot=True,
)

# Common Cyrillic and Greek homoglyphs mimicking Latin letters
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a",  # Cyrillic small a
    "\u0441": "c",  # Cyrillic small es
    "\u0435": "e",  # Cyrillic small ie
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small je
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0445": "x",  # Cyrillic small ha
    "\u0443": "y",  # Cyrillic small u
    "\u0455": "s",  # Cyrillic small dze
    "\u0454": "e",  # Cyrillic small Ukrainian ie
    "\u03bf": "o",  # Greek small omicron
    "\u03bd": "v",  # Greek small nu
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate the YAML configuration file."""
    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    
    # Check environment variable
    env_cfg = os.environ.get("MAILGUARD_CONFIG")
    if env_cfg:
        candidates.append(Path(env_cfg))
        
    # Check relative to working directory or project root
    candidates.extend([
        Path("config.yaml"),
        Path(__file__).resolve().parent.parent / "config.yaml",
        Path.home() / ".config" / "mailguard" / "config.yaml",
    ])

    loaded_path: Optional[Path] = None
    for p in candidates:
        if p.is_file():
            loaded_path = p
            break

    if not loaded_path:
        logger.warning("No config.yaml found in search paths; using built-in default settings.")
        return _get_default_config()

    try:
        with open(loaded_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            logger.debug(f"Loaded configuration from {loaded_path}")
            return _validate_and_merge_defaults(cfg)
    except Exception as e:
        logger.error(f"Failed to read configuration file {loaded_path}: {e}")
        return _get_default_config()


def _get_default_config() -> Dict[str, Any]:
    """Default fallback configuration."""
    return {
        "verdict_thresholds": {"legitimate_max": 30, "suspicious_max": 69},
        "auth_weights": {
            "spf_fail": 30,
            "spf_softfail": 15,
            "spf_permerror": 10,
            "spf_temperror": 5,
            "dkim_fail": 35,
            "dkim_missing": 10,
            "dkim_expired": 15,
            "dmarc_fail": 40,
            "dmarc_missing": 10,
            "spf_alignment_fail": 15,
            "dkim_alignment_fail": 15,
        },
        "heuristic_weights": {
            "reply_to_mismatch": 15,
            "display_name_email_mismatch": 20,
            "brand_impersonation": 25,
            "lookalike_domain": 30,
            "unicode_punycode_domain": 20,
            "suspicious_tld": 15,
            "link_text_href_mismatch": 25,
            "url_shortener": 10,
            "url_ip_address": 20,
            "suspicious_url_scheme": 30,
            "double_extension_attachment": 35,
            "risky_attachment_extension": 30,
            "urgency_credentials_keyword": 15,
            "missing_malformed_message_id": 10,
            "suspicious_received_chain": 15,
            "untrusted_auth_results": 15,
            "sender_brand_similarity": 25,
        },
        "lists": {
            "suspicious_tlds": [".zip", ".mov", ".top", ".xyz", ".country", ".kim", ".work"],
            "trusted_brand_domains": [
                "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
                "chase.com", "wellsfargo.com", "bankofamerica.com", "github.com",
            ],
            "url_shorteners": ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"],
            "risky_attachment_extensions": [
                ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".xlsm", ".docm",
            ],
            "urgency_keywords": [
                "urgent", "immediate action", "account suspended", "verify your account",
                "password reset", "security alert", "unauthorized access", "wire transfer",
            ],
        },
        "limits": {
            "max_message_bytes": 26214400,
            "max_attachment_bytes": 10485760,
            "max_urls_to_analyze": 100,
            "lookalike_ratio_threshold": 80.0,
        },
        "dns": {
            "timeout_seconds": 3.0,
            "retries": 2,
            "cache_ttl_seconds": 300,
            "fixtures_file": "tests/fixtures/dns_records.json",
        },
        "paths": {
            "output_jsonl": "output/results.jsonl",
            "default_html_report": "output/report.html",
        },
        "splunk": {
            "hec_url_env": "SPLUNK_HEC_URL",
            "hec_token_env": "SPLUNK_HEC_TOKEN",
            "index": "security_lab",
            "sourcetype": "mailguard:analysis",
            "verify_ssl": True,
            "timeout_seconds": 5.0,
            "max_retries": 2,
        },
        "trusted_receivers": ["mail.example.com", "mx.example.org", "inbound.security.local"],
        "privacy": {"anonymize_recipients": False, "hash_recipient_emails": False},
        "enrichment": {"enabled": False, "cache_ttl_seconds": 3600, "timeout_seconds": 4.0},
    }


def _validate_and_merge_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Validate structure and fill missing keys with defaults."""
    default = _get_default_config()
    for section, val in default.items():
        if section not in cfg:
            cfg[section] = val
        elif isinstance(val, dict):
            for k, v in val.items():
                if k not in cfg[section]:
                    cfg[section][k] = v
    return cfg


def get_registrable_domain(domain_or_email: Optional[str]) -> str:
    """Extract organizational (registrable) domain from a hostname or email address."""
    if not domain_or_email:
        return ""
    target = domain_or_email.strip().lower()
    if "@" in target:
        target = target.split("@")[-1].strip()
    # Strip any port or trailing dots
    target = target.split(":")[0].rstrip(".")
    if not target:
        return ""

    try:
        extracted = _OFFLINE_TLD_EXTRACTOR(target)
        # Use modern top_domain_under_public_suffix to avoid deprecation warnings
        reg_domain = getattr(extracted, "top_domain_under_public_suffix", None)
        if reg_domain:
            return reg_domain.lower()
        if extracted.domain:
            if extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
            return extracted.domain.lower()
        return target
    except Exception as e:
        logger.debug(f"tldextract failed on {target}: {e}")
        # Fallback heuristic
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target


def is_ip_address(host: str) -> bool:
    """Return True if string represents a valid IPv4 or IPv6 address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, link-local, multicast, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def sanitize_header(text: Optional[str]) -> str:
    """Sanitize header string by removing newlines, control characters, and excess whitespace."""
    if not text:
        return ""
    cleaned = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", str(text))
    return cleaned.strip()


def check_homoglyph_or_punycode(domain: str) -> Tuple[bool, str]:
    """Detect if a domain uses Punycode (IDN) or Cyrillic/Greek homoglyphs."""
    if not domain:
        return False, ""
    dom = domain.strip().lower()
    if "xn--" in dom:
        return True, f"Punycode encoded domain ({dom})"

    # Check for homoglyphs
    found_homoglyphs = []
    for char in dom:
        if char in HOMOGLYPH_MAP:
            found_homoglyphs.append(f"'{char}' (homoglyph of '{HOMOGLYPH_MAP[char]}')")

    if found_homoglyphs:
        return True, f"Homoglyphs detected: {', '.join(found_homoglyphs[:3])}"

    return False, ""


def safe_html(text: Optional[str]) -> str:
    """Safely escape text for HTML output to prevent XSS."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)
