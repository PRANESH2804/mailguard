"""Identifier alignment module for SPF and DKIM compliant with RFC 7489 (DMARC)."""

from __future__ import annotations

import logging
from typing import List, Optional

from mailguard.models import AlignmentResult
from mailguard.utils import get_registrable_domain

logger = logging.getLogger(__name__)


class IdentifierAlignment:
    """Evaluates strict and relaxed domain alignment between visible From and SPF/DKIM authenticated domains."""

    def evaluate(
        self,
        visible_from_domain: str,
        spf_domain: Optional[str],
        dkim_domains: List[str],
    ) -> AlignmentResult:
        norm_from = (visible_from_domain or "").strip().lower()
        norm_spf = (spf_domain or "").strip().lower() if spf_domain else None
        norm_dkims = [d.strip().lower() for d in dkim_domains if d]

        from_org = get_registrable_domain(norm_from)

        # 1. SPF Alignment
        spf_strict = False
        spf_relaxed = False
        if norm_spf:
            spf_org = get_registrable_domain(norm_spf)
            # Strict: exact match
            spf_strict = (norm_from == norm_spf) and bool(norm_from)
            # Relaxed: organizational domain match
            spf_relaxed = (from_org == spf_org) and bool(from_org)

        # 2. DKIM Alignment
        dkim_strict = False
        dkim_relaxed = False
        for dkim_dom in norm_dkims:
            dkim_org = get_registrable_domain(dkim_dom)
            if norm_from == dkim_dom and norm_from:
                dkim_strict = True
            if from_org == dkim_org and from_org:
                dkim_relaxed = True

        # Human-readable summary
        details_list = []
        if spf_strict:
            details_list.append("SPF strict alignment satisfied")
        elif spf_relaxed:
            details_list.append("SPF relaxed alignment satisfied (subdomain to org domain)")
        elif norm_spf:
            details_list.append(f"SPF unaligned (From: {norm_from} vs Return-Path: {norm_spf})")

        if dkim_strict:
            details_list.append("DKIM strict alignment satisfied")
        elif dkim_relaxed:
            details_list.append("DKIM relaxed alignment satisfied")
        elif norm_dkims:
            details_list.append(f"DKIM unaligned (From: {norm_from} vs d={', '.join(norm_dkims)})")

        if not details_list:
            details_list.append("No authenticated domains available for alignment check")

        return AlignmentResult(
            visible_from_domain=norm_from,
            spf_domain=norm_spf,
            dkim_domains=norm_dkims,
            spf_aligned_strict=spf_strict,
            spf_aligned_relaxed=spf_relaxed,
            dkim_aligned_strict=dkim_strict,
            dkim_aligned_relaxed=dkim_relaxed,
            details="; ".join(details_list),
        )
