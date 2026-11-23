"""Deterministic risk scoring and verdict classification module."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from mailguard.models import (
    AlignmentResult,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    HeuristicFinding,
    RecommendedAction,
    Severity,
    SPFResult,
    Verdict,
)
from mailguard.utils import load_config

logger = logging.getLogger(__name__)


class RiskScorer:
    """Calculates explainable risk scores (0-100) and assigns defensive verdicts."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        thresholds = self.config.get("verdict_thresholds", {})
        self.legitimate_max = int(thresholds.get("legitimate_max", 30))
        self.suspicious_max = int(thresholds.get("suspicious_max", 69))
        self.auth_weights = self.config.get("auth_weights", {})

    def calculate(
        self,
        spf: SPFResult,
        dkim: DKIMResult,
        dmarc: DMARCResult,
        alignment: AlignmentResult,
        heuristics: List[HeuristicFinding],
    ) -> Tuple[int, Verdict, List[str]]:
        """Compute the composite risk score, assign verdict, and return top contributing reasons."""
        contributions: List[Tuple[int, str]] = []

        # 1. SPF Score Contribution
        spf_score, spf_reason = self._score_spf(spf)
        if spf_score > 0:
            contributions.append((spf_score, spf_reason))

        # 2. DKIM Score Contribution
        dkim_score, dkim_reason = self._score_dkim(dkim)
        if dkim_score > 0:
            contributions.append((dkim_score, dkim_reason))

        # 3. DMARC Score Contribution
        dmarc_score, dmarc_reason = self._score_dmarc(dmarc)
        if dmarc_score > 0:
            contributions.append((dmarc_score, dmarc_reason))

        # 4. Alignment Contribution (only if not already completely penalized by DMARC fail)
        align_score, align_reason = self._score_alignment(alignment, dmarc)
        if align_score > 0:
            contributions.append((align_score, align_reason))

        # 5. Heuristics with Correlation De-duplication
        heur_contributions = self._score_heuristics(heuristics)
        contributions.extend(heur_contributions)

        # Sum total raw score
        total_score = sum(c[0] for c in contributions)

        # Clamp score strictly between 0 and 100
        clamped_score = max(0, min(100, int(round(total_score))))

        # Determine verdict
        verdict = self.classify_verdict(clamped_score)

        # Sort contributions descending to extract top reasons
        contributions.sort(key=lambda x: x[0], reverse=True)
        top_reasons = [f"{desc} (+{pts})" for pts, desc in contributions[:5]]
        if not top_reasons:
            top_reasons = ["All email authentication checks passed with zero suspicious indicators."]

        return clamped_score, verdict, top_reasons

    def classify_verdict(self, score: int) -> Verdict:
        """Classify numerical risk score into defensive verdict."""
        if score <= self.legitimate_max:
            return Verdict.LEGITIMATE
        elif score <= self.suspicious_max:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.SPOOFED

    def derive_recommended_action(
        self,
        verdict: Verdict,
        heuristics: Optional[List[HeuristicFinding]] = None,
        attachments: Optional[List[Any]] = None,
    ) -> RecommendedAction:
        """Derive actionable advisory recommendation for SOC operations.

        Advisory only; never executes remediation automatically:
        - ESCALATE_TO_SOC: Assigned for SPOOFED verdict or any high-risk attachment finding.
        - QUARANTINE_AND_REVIEW: Assigned for SUSPICIOUS verdict.
        - ALLOW: Assigned for LEGITIMATE verdict.
        """
        has_risky_attachment = False
        if attachments:
            for att in attachments:
                if getattr(att, "is_risky", False) or getattr(att, "is_double_extension", False):
                    has_risky_attachment = True
                    break
        if heuristics:
            for h in heuristics:
                h_id = getattr(h, "id", "")
                h_sev = getattr(h, "severity", "")
                if h_id in ("SUSP_ATTACHMENT_RISKY_EXT", "SUSP_ATTACHMENT_DOUBLE_EXT"):
                    has_risky_attachment = True
                    break
                if "attachment" in h_id.lower() and h_sev in (Severity.HIGH, Severity.CRITICAL, "HIGH", "CRITICAL"):
                    has_risky_attachment = True
                    break

        if verdict == Verdict.SPOOFED or has_risky_attachment:
            return RecommendedAction.ESCALATE_TO_SOC
        elif verdict == Verdict.SUSPICIOUS:
            return RecommendedAction.QUARANTINE_AND_REVIEW
        return RecommendedAction.ALLOW

    def _score_spf(self, spf: SPFResult) -> Tuple[int, str]:
        if spf.status == AuthStatus.FAIL:
            pts = int(self.auth_weights.get("spf_fail", 30))
            return pts, f"SPF evaluation returned hard FAIL for {spf.domain}"
        elif spf.status == AuthStatus.SOFTFAIL:
            pts = int(self.auth_weights.get("spf_softfail", 15))
            return pts, f"SPF evaluation returned SOFTFAIL for {spf.domain}"
        elif spf.status == AuthStatus.PERMERROR:
            pts = int(self.auth_weights.get("spf_permerror", 10))
            return pts, f"SPF permanent configuration error for {spf.domain}"
        elif spf.status == AuthStatus.TEMPERROR:
            pts = int(self.auth_weights.get("spf_temperror", 5))
            return pts, f"SPF DNS temporary lookup error for {spf.domain}"
        return 0, ""

    def _score_dkim(self, dkim: DKIMResult) -> Tuple[int, str]:
        if dkim.overall_status == AuthStatus.FAIL:
            pts = int(self.auth_weights.get("dkim_fail", 35))
            return pts, "DKIM signature cryptographic verification failed"
        elif dkim.overall_status == AuthStatus.NONE:
            pts = int(self.auth_weights.get("dkim_missing", 10))
            return pts, "No DKIM signature present on message"
        elif any(s.error and "expired" in s.error.lower() for s in dkim.signatures):
            pts = int(self.auth_weights.get("dkim_expired", 15))
            return pts, "DKIM signature has expired"
        return 0, ""

    def _score_dmarc(self, dmarc: DMARCResult) -> Tuple[int, str]:
        if dmarc.status == AuthStatus.FAIL:
            pts = int(self.auth_weights.get("dmarc_fail", 40))
            return pts, f"DMARC validation failed (policy={dmarc.policy})"
        elif dmarc.status == AuthStatus.NONE:
            pts = int(self.auth_weights.get("dmarc_missing", 10))
            return pts, "No DMARC policy record published by sender domain"
        elif dmarc.status in (AuthStatus.PERMERROR, AuthStatus.TEMPERROR):
            return 10, f"DMARC policy evaluation error: {dmarc.explanation}"
        return 0, ""

    def _score_alignment(self, alignment: AlignmentResult, dmarc: DMARCResult) -> Tuple[int, str]:
        # If DMARC already penalized heavily, avoid full double penalty
        if dmarc.status == AuthStatus.FAIL:
            return 0, ""
        
        pts = 0
        reasons = []
        if alignment.spf_domain and not alignment.spf_aligned_relaxed:
            sub_pts = int(self.auth_weights.get("spf_alignment_fail", 15))
            pts += sub_pts
            reasons.append(f"SPF Return-Path ({alignment.spf_domain}) does not align with From ({alignment.visible_from_domain})")

        if alignment.dkim_domains and not alignment.dkim_aligned_relaxed:
            sub_pts = int(self.auth_weights.get("dkim_alignment_fail", 15))
            pts += sub_pts
            reasons.append("DKIM signing domain does not align with visible From")

        if pts > 0:
            return pts, "; ".join(reasons)
        return 0, ""

    def _score_heuristics(self, heuristics: List[HeuristicFinding]) -> List[Tuple[int, str]]:
        results: List[Tuple[int, str]] = []

        # Correlated brand impersonation cap to prevent artificial inflation
        brand_findings = [h for h in heuristics if "brand" in h.id.lower() or "lookalike" in h.id.lower()]
        other_findings = [h for h in heuristics if h not in brand_findings]

        for h in other_findings:
            results.append((h.weight, f"{h.name}: {h.description[:60]}..."))

        # Cap brand findings to max 45 points combined
        if brand_findings:
            raw_brand_sum = sum(h.weight for h in brand_findings)
            capped_brand_pts = min(45, raw_brand_sum)
            top_brand_name = brand_findings[0].name
            results.append((capped_brand_pts, f"{top_brand_name} and related impersonation markers"))

        return results
