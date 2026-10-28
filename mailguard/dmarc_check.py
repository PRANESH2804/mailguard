"""DMARC (Domain-based Message Authentication, Reporting, and Conformance) evaluation module (RFC 7489)."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from mailguard.alignment import IdentifierAlignment
from mailguard.dns_resolver import BaseDNSResolver, DNSTimeoutError, LiveDNSResolver
from mailguard.models import (
    AlignmentResult,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    ParsedEmail,
    SPFResult,
)
from mailguard.utils import get_registrable_domain

logger = logging.getLogger(__name__)


class DMARCChecker:
    """Evaluates RFC 7489 DMARC policy compliance and identifier alignment."""

    def __init__(self, resolver: Optional[BaseDNSResolver] = None):
        self.resolver = resolver or LiveDNSResolver()
        self.alignment = IdentifierAlignment()

    def evaluate(
        self,
        parsed_email: ParsedEmail,
        spf_result: SPFResult,
        dkim_result: DKIMResult,
    ) -> Tuple[DMARCResult, AlignmentResult]:
        """Evaluate DMARC compliance given SPF and DKIM evaluation results."""
        from_domain = parsed_email.from_domain
        if not from_domain:
            align_res = self.alignment.evaluate("", None, [])
            return (
                DMARCResult(
                    status=AuthStatus.NONE,
                    domain="",
                    org_domain=None,
                    policy="none",
                    subdomain_policy=None,
                    pct=100,
                    explanation="No RFC5322 From domain present to evaluate DMARC",
                ),
                align_res,
            )

        org_domain = get_registrable_domain(from_domain)
        is_subdomain = from_domain.lower() != org_domain.lower()

        # Step 1: Query DMARC record with organizational domain fallback
        record_raw, dmarc_query_domain, err = self._lookup_dmarc_record(from_domain, org_domain)
        if err:
            align_res = self._compute_alignment(parsed_email, dkim_result)
            status = AuthStatus.TEMPERROR if "timeout" in err.lower() else AuthStatus.PERMERROR
            return (
                DMARCResult(
                    status=status,
                    domain=from_domain,
                    org_domain=org_domain,
                    policy="none",
                    subdomain_policy=None,
                    explanation=f"DMARC DNS lookup error: {err}",
                    error=err,
                ),
                align_res,
            )

        if not record_raw:
            align_res = self._compute_alignment(parsed_email, dkim_result)
            return (
                DMARCResult(
                    status=AuthStatus.NONE,
                    domain=from_domain,
                    org_domain=org_domain,
                    policy="none",
                    subdomain_policy=None,
                    explanation=f"No DMARC TXT record found for _dmarc.{from_domain} or _dmarc.{org_domain}",
                ),
                align_res,
            )

        # Step 2: Parse DMARC tags
        tags, parse_err = self._parse_dmarc_tags(record_raw)
        if parse_err:
            align_res = self._compute_alignment(parsed_email, dkim_result)
            return (
                DMARCResult(
                    status=AuthStatus.PERMERROR,
                    domain=from_domain,
                    org_domain=org_domain,
                    policy="none",
                    subdomain_policy=None,
                    record_raw=record_raw,
                    explanation=f"Invalid DMARC record syntax: {parse_err}",
                    error=parse_err,
                ),
                align_res,
            )

        published_p = tags.get("p", "none").lower()
        published_sp = tags.get("sp", "").lower() or None
        aspf_mode = tags.get("aspf", "r").lower()
        adkim_mode = tags.get("adkim", "r").lower()
        pct_val = int(tags.get("pct", "100"))

        # Determine effective policy for this message
        if is_subdomain and published_sp:
            effective_policy = published_sp
        else:
            effective_policy = published_p

        # Step 3: Compute alignment
        align_res = self._compute_alignment(parsed_email, dkim_result)

        # Step 4: Evaluate DMARC pass conditions
        # SPF aligned pass:
        spf_aligned = align_res.spf_aligned_strict if aspf_mode == "s" else align_res.spf_aligned_relaxed
        spf_pass = (spf_result.status == AuthStatus.PASS) and spf_aligned

        # DKIM aligned pass:
        dkim_pass = False
        for sig in dkim_result.signatures:
            if sig.verification_status == AuthStatus.PASS:
                sig_dom = sig.signing_domain.lower()
                sig_org = get_registrable_domain(sig_dom)
                aligned = (from_domain == sig_dom) if adkim_mode == "s" else (org_domain == sig_org)
                if aligned:
                    dkim_pass = True
                    break

        dmarc_passed = spf_pass or dkim_pass
        final_status = AuthStatus.PASS if dmarc_passed else AuthStatus.FAIL

        # Construct explanation
        reasons: List[str] = []
        if spf_pass:
            reasons.append("SPF authenticated and aligned")
        else:
            reasons.append("SPF failed or unaligned")

        if dkim_pass:
            reasons.append("DKIM authenticated and aligned")
        else:
            reasons.append("DKIM failed or unaligned")

        explanation = f"DMARC {final_status.value} (policy={effective_policy}, pct={pct_val}%): {', '.join(reasons)}"

        return (
            DMARCResult(
                status=final_status,
                domain=from_domain,
                org_domain=org_domain,
                policy=effective_policy,
                subdomain_policy=published_sp,
                pct=pct_val,
                spf_aligned_pass=spf_pass,
                dkim_aligned_pass=dkim_pass,
                record_raw=record_raw,
                explanation=explanation,
            ),
            align_res,
        )

    def _compute_alignment(self, parsed_email: ParsedEmail, dkim_result: DKIMResult) -> AlignmentResult:
        dkim_domains = [s.signing_domain for s in dkim_result.signatures]
        spf_domain = parsed_email.return_path_domain
        return self.alignment.evaluate(
            visible_from_domain=parsed_email.from_domain,
            spf_domain=spf_domain,
            dkim_domains=dkim_domains,
        )

    def _lookup_dmarc_record(
        self, from_domain: str, org_domain: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Look up _dmarc TXT record with organizational domain fallback."""
        dmarc_name = f"_dmarc.{from_domain}"
        try:
            records = self.resolver.query_txt(dmarc_name)
            dmarc_recs = [r for r in records if "v=dmarc1" in r.lower()]
            if len(dmarc_recs) > 1:
                return None, dmarc_name, "Multiple conflicting DMARC records found in DNS"
            if len(dmarc_recs) == 1:
                return dmarc_recs[0], dmarc_name, None
        except DNSTimeoutError as te:
            return None, dmarc_name, str(te)
        except Exception as e:
            logger.debug(f"Query for {dmarc_name} failed: {e}")

        # Fallback to organizational domain if subdomain
        if from_domain.lower() != org_domain.lower() and org_domain:
            org_dmarc_name = f"_dmarc.{org_domain}"
            try:
                records = self.resolver.query_txt(org_dmarc_name)
                dmarc_recs = [r for r in records if "v=dmarc1" in r.lower()]
                if len(dmarc_recs) > 1:
                    return None, org_dmarc_name, "Multiple conflicting DMARC records found in DNS"
                if len(dmarc_recs) == 1:
                    return dmarc_recs[0], org_dmarc_name, None
            except DNSTimeoutError as te:
                return None, org_dmarc_name, str(te)
            except Exception as e:
                logger.debug(f"Query for {org_dmarc_name} failed: {e}")

        return None, None, None

    def _parse_dmarc_tags(self, record_raw: str) -> Tuple[Dict[str, str], Optional[str]]:
        """Parse and validate RFC 7489 DMARC record tags."""
        tags: Dict[str, str] = {}
        parts = [p.strip() for p in record_raw.split(";") if p.strip()]

        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        if "v" not in tags or tags["v"].upper() != "DMARC1":
            return {}, "Missing or invalid DMARC version tag (must start with v=DMARC1)"

        if "p" not in tags:
            return {}, "Missing required policy tag 'p='"

        valid_policies = {"none", "quarantine", "reject"}
        if tags["p"].lower() not in valid_policies:
            return {}, f"Invalid policy tag value: p={tags['p']}"

        if "pct" in tags:
            try:
                pct = int(tags["pct"])
                if not (0 <= pct <= 100):
                    return {}, f"Invalid pct value: {pct} (must be 0-100)"
            except ValueError:
                return {}, f"Invalid non-integer pct value: {tags['pct']}"

        return tags, None
