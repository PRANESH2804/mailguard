"""Unit tests for SOAR ticketing export schema, severity derivation, and file output."""

import json
from pathlib import Path
import pytest

from mailguard.models import (
    AlignmentResult,
    AnalysisResult,
    AttachmentInfo,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    MITREMapping,
    RecommendedAction,
    SPFResult,
    URLInfo,
    Verdict,
)
from mailguard.soar_export import derive_soar_severity, export_soar_ticket, generate_analyst_summary, save_soar_ticket


@pytest.fixture
def mock_analysis_result():
    return AnalysisResult(
        timestamp="2026-10-28T12:00:00+00:00",
        message_id="<soar-test-123@example.com>",
        subject="Urgent: Wire Transfer Verification Needed",
        from_address="security@example.com",
        from_domain="example.com",
        return_path="bounces@example.org",
        return_path_domain="example.org",
        originating_ip="198.51.100.25",
        recipients=["cfo@victimcorp.example.com"],
        spf=SPFResult(status=AuthStatus.FAIL, identity="bounces@example.org", domain="example.org"),
        dkim=DKIMResult(signatures=[], overall_status=AuthStatus.FAIL),
        dmarc=DMARCResult(status=AuthStatus.FAIL, domain="example.com", org_domain="example.com", policy="reject", subdomain_policy=None),
        alignment=AlignmentResult(visible_from_domain="example.com", spf_domain="example.org", dkim_domains=[]),
        heuristics=[],
        risk_score=85,
        verdict=Verdict.SPOOFED,
        recommended_action=RecommendedAction.ESCALATE_TO_SOC,
        top_reasons=["DMARC failed (+40)", "DKIM failed (+35)", "SPF hard fail (+30)"],
        mitre_techniques=[
            MITREMapping(
                technique_id="T1672",
                technique_name="Subvert Trust Controls: Email Spoofing",
                tactic="Defense Evasion",
                rationale="Sender failed authentication checks",
                finding_ids=["AUTH-SPF-FAIL", "AUTH-DKIM-FAIL"],
            )
        ],
        urls=[
            URLInfo(raw_url="http://198.51.100.25/login", scheme="http", domain="198.51.100.25", has_ip_host=True)
        ],
        attachments=[
            AttachmentInfo(
                filename="statement.pdf.exe",
                content_type="application/octet-stream",
                size_bytes=4096,
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                is_risky=True,
                is_double_extension=True,
            )
        ],
    )


def test_soar_export_schema_compliance(mock_analysis_result):
    ticket = export_soar_ticket(mock_analysis_result)

    # Verify root fields required by SOAR schema
    required_keys = {
        "id",
        "severity",
        "verdict",
        "recommended_action",
        "risk_score",
        "indicators",
        "reasons",
        "mitre_techniques",
        "short_analyst_summary",
    }
    assert set(ticket.keys()) == required_keys

    # Verify field types & contents
    assert ticket["id"].startswith("MG-")
    assert ticket["severity"] == "CRITICAL"
    assert ticket["verdict"] == "SPOOFED"
    assert ticket["recommended_action"] == "ESCALATE_TO_SOC"
    assert ticket["risk_score"] == 85

    # Verify indicator extraction
    indicators = ticket["indicators"]
    assert "example.com" in indicators["sender_domains"]
    assert "example.org" in indicators["sender_domains"]
    assert "198.51.100.25" in indicators["originating_ips"]
    assert "http://198.51.100.25/login" in indicators["urls"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in indicators["attachment_hashes"]

    # Verify MITRE techniques
    assert len(ticket["mitre_techniques"]) == 1
    assert ticket["mitre_techniques"][0]["id"] == "T1672"

    # Verify summary
    assert "SPOOFED" in ticket["short_analyst_summary"]
    assert "ESCALATE_TO_SOC" in ticket["short_analyst_summary"]


def test_soar_severity_mappings(mock_analysis_result):
    # CRITICAL: SPOOFED with score >= 85
    mock_analysis_result.risk_score = 90
    mock_analysis_result.verdict = Verdict.SPOOFED
    assert derive_soar_severity(mock_analysis_result) == "CRITICAL"

    # HIGH: SUSPICIOUS with risky attachment
    mock_analysis_result.verdict = Verdict.SUSPICIOUS
    mock_analysis_result.risk_score = 45
    assert derive_soar_severity(mock_analysis_result) == "HIGH"

    # MEDIUM: SUSPICIOUS without risky attachment and score < 50
    mock_analysis_result.attachments[0].is_risky = False
    mock_analysis_result.attachments[0].is_double_extension = False
    assert derive_soar_severity(mock_analysis_result) == "MEDIUM"

    # LOW: LEGITIMATE
    mock_analysis_result.verdict = Verdict.LEGITIMATE
    mock_analysis_result.risk_score = 10
    assert derive_soar_severity(mock_analysis_result) == "LOW"


def test_soar_save_file(tmp_path, mock_analysis_result):
    out_json = tmp_path / "soar_incident.json"
    saved_path = save_soar_ticket(mock_analysis_result, out_json)
    assert saved_path.is_file()

    with open(saved_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["id"].startswith("MG-")
        assert data["verdict"] == "SPOOFED"
