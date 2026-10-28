"""DKIM (DomainKeys Identified Mail) verification module compliant with RFC 6376."""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import dkim

from mailguard.dns_resolver import BaseDNSResolver, DNSTimeoutError, LiveDNSResolver
from mailguard.models import AuthStatus, DKIMResult, DKIMSignatureResult, ParsedEmail

logger = logging.getLogger(__name__)


class DKIMChecker:
    """Verifies DKIM signatures across raw message bytes using dkimpy and configured DNS resolvers."""

    def __init__(self, resolver: Optional[BaseDNSResolver] = None):
        self.resolver = resolver or LiveDNSResolver()

    def evaluate(self, parsed_email: ParsedEmail) -> DKIMResult:
        """Verify all DKIM signatures present on the raw email message."""
        raw_bytes = parsed_email.raw_bytes
        if not raw_bytes:
            return DKIMResult(
                signatures=[],
                overall_status=AuthStatus.NONE,
                explanation="No message content available to verify DKIM",
            )

        try:
            d = dkim.DKIM(raw_bytes)
        except Exception as e:
            logger.warning(f"Failed to initialize dkimpy DKIM object: {e}")
            return DKIMResult(
                signatures=[],
                overall_status=AuthStatus.PERMERROR,
                explanation=f"Malformed email structure prevented DKIM parsing: {e}",
            )

        if not d.present():
            # Check if an existing Authentication-Results header exists
            cached_sig = self._extract_from_auth_results(parsed_email)
            if cached_sig:
                return DKIMResult(
                    signatures=[cached_sig],
                    overall_status=cached_sig.verification_status,
                    explanation=f"DKIM result derived from existing Authentication-Results header ({cached_sig.explanation})",
                )

            return DKIMResult(
                signatures=[],
                overall_status=AuthStatus.NONE,
                explanation="No DKIM-Signature header present in message",
            )

        # Count how many DKIM-Signature headers are present
        dkim_headers: List[bytes] = []
        for h, v in d.headers:
            if h.lower() == b"dkim-signature":
                dkim_headers.append(v)

        signature_results: List[DKIMSignatureResult] = []

        for idx, raw_hdr in enumerate(dkim_headers):
            sig_tags = self._parse_tags(raw_hdr)
            sig_result = self._verify_single_signature(d, idx, sig_tags)
            signature_results.append(sig_result)

        # Aggregate overall status
        overall_status = AuthStatus.FAIL
        has_pass = any(s.verification_status == AuthStatus.PASS for s in signature_results)
        all_temperrors = all(s.verification_status == AuthStatus.TEMPERROR for s in signature_results)

        if has_pass:
            overall_status = AuthStatus.PASS
            explanation = f"DKIM verified successfully ({sum(1 for s in signature_results if s.verification_status == AuthStatus.PASS)} valid signature(s))"
        elif all_temperrors and signature_results:
            overall_status = AuthStatus.TEMPERROR
            explanation = "Temporary DNS failure prevented DKIM verification"
        else:
            overall_status = AuthStatus.FAIL
            fail_reasons = [f"d={s.signing_domain} ({s.explanation})" for s in signature_results]
            explanation = f"DKIM verification failed: {'; '.join(fail_reasons)}"

        return DKIMResult(
            signatures=signature_results,
            overall_status=overall_status,
            explanation=explanation,
        )

    def _parse_tags(self, raw_header: bytes) -> Dict[str, str]:
        """Extract DKIM tag-value pairs (d=, s=, a=, bh=, b=, x=, etc.)."""
        tags: Dict[str, str] = {}
        try:
            text = raw_header.decode("utf-8", errors="replace")
        except Exception:
            text = str(raw_header)

        # Remove folding whitespace
        unfolded = re.sub(r"[\r\n\t]+", " ", text)
        parts = unfolded.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    def _verify_single_signature(
        self, d: dkim.DKIM, idx: int, tags: Dict[str, str]
    ) -> DKIMSignatureResult:
        signing_domain = tags.get("d", "unknown")
        selector = tags.get("s", "unknown")
        algorithm = tags.get("a", "rsa-sha256")
        body_hash = tags.get("bh", "")
        expires_tag = tags.get("x")

        # Expiration check
        expires_at = None
        is_expired = False
        if expires_tag and expires_tag.isdigit():
            exp_ts = int(expires_tag)
            expires_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp_ts))
            if time.time() > exp_ts:
                is_expired = True

        # Custom DNS query wrapper for dkimpy
        def custom_dns(name: Union[bytes, str], timeout: int = 5) -> bytes:
            return self.resolver.dkim_dns_lookup(name, timeout=timeout)

        body_hash_status = "UNKNOWN"
        status = AuthStatus.FAIL
        error = None
        explanation = ""

        try:
            valid = d.verify(idx=idx, dnsfunc=custom_dns)
            if is_expired:
                body_hash_status = "PASS" if valid else "UNKNOWN"
                status = AuthStatus.FAIL
                explanation = f"DKIM signature expired on {expires_at}"
                error = "Signature expired"
            elif valid:
                body_hash_status = "PASS"
                status = AuthStatus.PASS
                explanation = f"Cryptographically valid signature for d={signing_domain}"
            else:
                body_hash_status = "PASS"
                status = AuthStatus.FAIL
                explanation = "RSA/Ed25519 signature verification failed (content modified or invalid signature)"
                error = "Signature mismatch"
        except dkim.ValidationError as ve:
            msg = str(ve).lower()
            if "body hash mismatch" in msg:
                body_hash_status = "FAIL"
                status = AuthStatus.FAIL
                explanation = "DKIM body hash mismatch (body altered in transit)"
                error = str(ve)
            elif "x=" in msg or is_expired:
                body_hash_status = "FAIL"
                status = AuthStatus.FAIL
                explanation = f"DKIM signature expired on {expires_at or 'past timestamp'}: {ve}"
                error = "Signature expired"
            else:
                body_hash_status = "FAIL"
                status = AuthStatus.FAIL
                explanation = f"DKIM validation error: {ve}"
                error = str(ve)
        except dkim.KeyFormatError as kfe:
            body_hash_status = "UNKNOWN"
            status = AuthStatus.PERMERROR
            explanation = f"Malformed DKIM public key in DNS: {kfe}"
            error = str(kfe)
        except DNSTimeoutError as te:
            body_hash_status = "UNKNOWN"
            status = AuthStatus.TEMPERROR
            explanation = f"DNS timeout retrieving DKIM public key for {selector}._domainkey.{signing_domain}"
            error = str(te)
        except Exception as e:
            err_msg = str(e).lower()
            if "not found" in err_msg or "nxdomain" in err_msg or "no txt record" in err_msg:
                body_hash_status = "UNKNOWN"
                status = AuthStatus.PERMERROR
                explanation = f"DKIM public key not found in DNS for selector '{selector}' and domain '{signing_domain}'"
                error = "Key not found"
            else:
                body_hash_status = "UNKNOWN"
                status = AuthStatus.PERMERROR
                explanation = f"DKIM verification failed: {e}"
                error = str(e)

        return DKIMSignatureResult(
            signing_domain=signing_domain,
            selector=selector,
            algorithm=algorithm,
            body_hash_status=body_hash_status,
            verification_status=status,
            explanation=explanation,
            error=error,
            expires_at=expires_at,
        )

    def _extract_from_auth_results(self, parsed_email: ParsedEmail) -> Optional[DKIMSignatureResult]:
        for header in parsed_email.auth_results_headers:
            header_lower = header.lower()
            if "dkim=" in header_lower:
                for token in header_lower.split(";"):
                    token = token.strip()
                    if token.startswith("dkim="):
                        val_parts = token.split("=")[1].split()
                        val = val_parts[0].strip()
                        # Extract header.d if present
                        d_match = re.search(r"header\.d=([^\s;]+)", header_lower)
                        signing_domain = d_match.group(1) if d_match else (parsed_email.from_domain or "unknown")
                        
                        status = AuthStatus.PASS if val == "pass" else AuthStatus.FAIL
                        return DKIMSignatureResult(
                            signing_domain=signing_domain,
                            selector="auth-results-cached",
                            algorithm="unknown",
                            body_hash_status="PASS" if status == AuthStatus.PASS else "FAIL",
                            verification_status=status,
                            explanation=f"Authentication-Results header indicates dkim={val}",
                        )
        return None
