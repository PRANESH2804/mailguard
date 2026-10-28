"""SPF (Sender Policy Framework) evaluation module leveraging pyspf and custom DNS resolution."""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional, Tuple

import spf

from mailguard.dns_resolver import BaseDNSResolver, LiveDNSResolver, OfflineDNSResolver
from mailguard.models import AuthStatus, ParsedEmail, SPFResult

logger = logging.getLogger(__name__)

_SPF_LOCK = threading.Lock()


class SPFChecker:
    """Evaluates Sender Policy Framework (RFC 7208) for parsed email messages."""

    def __init__(self, resolver: Optional[BaseDNSResolver] = None, trusted_receivers: Optional[list[str]] = None):
        self.resolver = resolver or LiveDNSResolver()
        self.trusted_receivers = [r.lower() for r in (trusted_receivers or [])]

    def evaluate(self, parsed_email: ParsedEmail) -> SPFResult:
        """Evaluate SPF against the originating IP and Return-Path envelope sender."""
        ip = parsed_email.candidate_originating_ip
        sender = parsed_email.return_path or parsed_email.from_address
        domain = parsed_email.return_path_domain or parsed_email.from_domain

        if not domain:
            return SPFResult(
                status=AuthStatus.NONE,
                identity="unknown",
                domain="",
                explanation="No valid sender domain available to evaluate SPF",
            )

        if not ip:
            # Check if an existing Authentication-Results header exists
            cached_status, header_expl = self._extract_from_auth_results(parsed_email)
            if cached_status != AuthStatus.UNKNOWN:
                return SPFResult(
                    status=cached_status,
                    identity=sender or domain,
                    domain=domain,
                    explanation=f"Evaluated from existing Authentication-Results header ({header_expl})",
                )

            return SPFResult(
                status=AuthStatus.UNKNOWN,
                identity=sender or domain,
                domain=domain,
                explanation="Originating client IP could not be reliably determined from Received headers",
            )

        # Execute SPF evaluation via pyspf using custom resolver hook
        status, explanation, mechanism, error = self._run_pyspf(ip=ip, sender=sender, domain=domain)
        return SPFResult(
            status=status,
            identity=sender or domain,
            domain=domain,
            mechanism=mechanism,
            explanation=explanation,
            error=error,
        )

    def _run_pyspf(self, ip: str, sender: str, domain: str) -> Tuple[AuthStatus, str, Optional[str], Optional[str]]:
        helo = domain
        with _SPF_LOCK:
            orig_lookup = spf.DNSLookup
            try:
                # Intercept DNS lookups via our resolver
                spf.DNSLookup = self.resolver.spf_dns_lookup
                # Evaluate using pyspf check2
                result, explanation = spf.check2(i=ip, s=sender, h=helo)
            except Exception as e:
                logger.warning(f"pyspf check2 encountered exception for {domain} ({ip}): {e}")
                return AuthStatus.PERMERROR, f"SPF evaluation error: {e}", None, str(e)
            finally:
                spf.DNSLookup = orig_lookup

        res_lower = str(result).lower().strip()
        mech = None
        if "mechanism" in explanation.lower():
            # Extract mechanism if mentioned in explanation
            parts = explanation.split("mechanism")
            if len(parts) > 1:
                mech = parts[1].strip()

        status_map: Dict[str, AuthStatus] = {
            "pass": AuthStatus.PASS,
            "fail": AuthStatus.FAIL,
            "softfail": AuthStatus.SOFTFAIL,
            "neutral": AuthStatus.NEUTRAL,
            "none": AuthStatus.NONE,
            "permerror": AuthStatus.PERMERROR,
            "temperror": AuthStatus.TEMPERROR,
        }

        auth_status = status_map.get(res_lower, AuthStatus.UNKNOWN)
        return auth_status, explanation, mech, None

    def _extract_from_auth_results(self, parsed_email: ParsedEmail) -> Tuple[AuthStatus, str]:
        """Examine pre-existing Authentication-Results headers as fallback evidence."""
        for header in parsed_email.auth_results_headers:
            header_lower = header.lower()
            if "spf=" in header_lower:
                for token in header_lower.split(";"):
                    token = token.strip()
                    if token.startswith("spf="):
                        val = token.split("=")[1].split()[0].strip()
                        is_trusted = any(tr in header_lower for tr in self.trusted_receivers)
                        trust_note = "trusted receiver" if is_trusted else "unverified source"
                        if val == "pass":
                            return AuthStatus.PASS, f"SPF pass ({trust_note})"
                        elif val == "fail":
                            return AuthStatus.FAIL, f"SPF fail ({trust_note})"
                        elif val == "softfail":
                            return AuthStatus.SOFTFAIL, f"SPF softfail ({trust_note})"
                        elif val == "neutral":
                            return AuthStatus.NEUTRAL, f"SPF neutral ({trust_note})"
                        elif val == "none":
                            return AuthStatus.NONE, f"SPF none ({trust_note})"
        return AuthStatus.UNKNOWN, "No SPF evidence found in Authentication-Results"
