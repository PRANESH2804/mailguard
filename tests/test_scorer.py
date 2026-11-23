"""Unit tests for the RiskScorer covering boundary conditions (0, 30, 31, 69, 70, 100)."""

import pytest

from mailguard.models import (
    AlignmentResult,
    AttachmentInfo,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    HeuristicFinding,
    RecommendedAction,
    Severity,
    SPFResult,
    Verdict,
)
from mailguard.scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def test_scorer_boundary_0_legitimate(scorer):
    spf = SPFResult(status=AuthStatus.PASS, identity="a@b.com", domain="b.com")
    dkim = DKIMResult(signatures=[], overall_status=AuthStatus.PASS)
    dmarc = DMARCResult(status=AuthStatus.PASS, domain="b.com", org_domain="b.com", policy="reject", subdomain_policy=None)
    align = AlignmentResult(visible_from_domain="b.com", spf_domain="b.com", dkim_domains=["b.com"], spf_aligned_relaxed=True, dkim_aligned_relaxed=True)

    score, verdict, reasons = scorer.calculate(spf, dkim, dmarc, align, [])
    assert score == 0
    assert verdict == Verdict.LEGITIMATE


def test_scorer_boundary_30_legitimate(scorer):
    # A single SPF hard fail (+30) without any other findings = exactly 30 -> LEGITIMATE
    spf = SPFResult(status=AuthStatus.FAIL, identity="a@b.com", domain="b.com")
    dkim = DKIMResult(signatures=[], overall_status=AuthStatus.PASS)
    dmarc = DMARCResult(status=AuthStatus.PASS, domain="b.com", org_domain="b.com", policy="none", subdomain_policy=None)
    align = AlignmentResult(visible_from_domain="b.com", spf_domain="b.com", dkim_domains=["b.com"], spf_aligned_relaxed=True, dkim_aligned_relaxed=True)

    score, verdict, _ = scorer.calculate(spf, dkim, dmarc, align, [])
    assert score == 30
    assert verdict == Verdict.LEGITIMATE


def test_scorer_boundary_31_suspicious(scorer):
    # Score of 31 is SUSPICIOUS
    assert scorer.classify_verdict(31) == Verdict.SUSPICIOUS


def test_scorer_boundary_69_suspicious(scorer):
    # Score of 69 is SUSPICIOUS
    assert scorer.classify_verdict(69) == Verdict.SUSPICIOUS


def test_scorer_boundary_70_spoofed(scorer):
    # Score of 70 is SPOOFED
    assert scorer.classify_verdict(70) == Verdict.SPOOFED


def test_scorer_boundary_100_spoofed(scorer):
    # Full failure: SPF fail (30) + DKIM fail (35) + DMARC fail (40) = 105 -> Clamped to 100
    spf = SPFResult(status=AuthStatus.FAIL, identity="a@b.com", domain="b.com")
    dkim = DKIMResult(signatures=[], overall_status=AuthStatus.FAIL)
    dmarc = DMARCResult(status=AuthStatus.FAIL, domain="b.com", org_domain="b.com", policy="reject", subdomain_policy=None)
    align = AlignmentResult(visible_from_domain="b.com", spf_domain="b.com", dkim_domains=["b.com"])

    score, verdict, reasons = scorer.calculate(spf, dkim, dmarc, align, [])
    assert score == 100
    assert verdict == Verdict.SPOOFED
    assert len(reasons) >= 3


def test_scorer_recommended_actions_boundaries(scorer):
    # Boundary 0: LEGITIMATE -> ALLOW
    assert scorer.derive_recommended_action(Verdict.LEGITIMATE) == RecommendedAction.ALLOW
    
    # Boundary 30: LEGITIMATE -> ALLOW
    v_30 = scorer.classify_verdict(30)
    assert v_30 == Verdict.LEGITIMATE
    assert scorer.derive_recommended_action(v_30) == RecommendedAction.ALLOW

    # Boundary 31: SUSPICIOUS -> QUARANTINE_AND_REVIEW
    v_31 = scorer.classify_verdict(31)
    assert v_31 == Verdict.SUSPICIOUS
    assert scorer.derive_recommended_action(v_31) == RecommendedAction.QUARANTINE_AND_REVIEW

    # Boundary 69: SUSPICIOUS -> QUARANTINE_AND_REVIEW
    v_69 = scorer.classify_verdict(69)
    assert v_69 == Verdict.SUSPICIOUS
    assert scorer.derive_recommended_action(v_69) == RecommendedAction.QUARANTINE_AND_REVIEW

    # Boundary 70: SPOOFED -> ESCALATE_TO_SOC
    v_70 = scorer.classify_verdict(70)
    assert v_70 == Verdict.SPOOFED
    assert scorer.derive_recommended_action(v_70) == RecommendedAction.ESCALATE_TO_SOC

    # Boundary 100: SPOOFED -> ESCALATE_TO_SOC
    v_100 = scorer.classify_verdict(100)
    assert v_100 == Verdict.SPOOFED
    assert scorer.derive_recommended_action(v_100) == RecommendedAction.ESCALATE_TO_SOC


def test_scorer_risky_attachment_escalates_even_if_legitimate(scorer):
    # Even if score is 0 / LEGITIMATE, a high-risk attachment finding MUST escalate to SOC
    finding = HeuristicFinding(
        id="SUSP_ATTACHMENT_RISKY_EXT",
        name="Executable/Script Attachment Extension",
        severity=Severity.HIGH,
        weight=25,
        description="Dangerous attachment detected",
        evidence="payload.exe",
    )
    action = scorer.derive_recommended_action(Verdict.LEGITIMATE, heuristics=[finding])
    assert action == RecommendedAction.ESCALATE_TO_SOC

    # Also test via AttachmentInfo is_risky flag
    att = AttachmentInfo(
        filename="invoice.pdf.exe",
        content_type="application/octet-stream",
        size_bytes=1024,
        sha256="abc",
        is_risky=True,
    )
    action_att = scorer.derive_recommended_action(Verdict.LEGITIMATE, attachments=[att])
    assert action_att == RecommendedAction.ESCALATE_TO_SOC

