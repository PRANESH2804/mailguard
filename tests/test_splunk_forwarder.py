"""Unit tests for Splunk HEC forwarder and local JSONL persistence."""

import json
from unittest.mock import MagicMock, patch
import pytest

from mailguard.models import (
    AlignmentResult,
    AnalysisResult,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    SPFResult,
    Verdict,
)
from mailguard.splunk_forwarder import SplunkForwarder


@pytest.fixture
def dummy_result():
    return AnalysisResult(
        timestamp="2026-10-28T10:00:00+00:00",
        message_id="<test@example.com>",
        subject="Test Alert",
        from_address="sender@example.com",
        from_domain="example.com",
        return_path="sender@example.com",
        return_path_domain="example.com",
        originating_ip="192.0.2.1",
        recipients=["admin@example.com"],
        spf=SPFResult(status=AuthStatus.PASS, identity="sender@example.com", domain="example.com"),
        dkim=DKIMResult(signatures=[], overall_status=AuthStatus.PASS),
        dmarc=DMARCResult(status=AuthStatus.PASS, domain="example.com", org_domain="example.com", policy="reject", subdomain_policy=None),
        alignment=AlignmentResult(visible_from_domain="example.com", spf_domain="example.com", dkim_domains=["example.com"]),
        heuristics=[],
        risk_score=0,
        verdict=Verdict.LEGITIMATE,
        top_reasons=["All authentication passed"],
        mitre_techniques=[],
        urls=[],
        attachments=[],
    )


def test_splunk_local_persistence(tmp_path, dummy_result):
    jsonl_file = tmp_path / "test_results.jsonl"
    forwarder = SplunkForwarder(config={"paths": {"output_jsonl": str(jsonl_file)}})

    success = forwarder.persist_locally(dummy_result)
    assert success is True
    assert jsonl_file.is_file()

    with open(jsonl_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["message_id"] == "<test@example.com>"
        assert data["verdict"] == "LEGITIMATE"


def test_splunk_hec_success(monkeypatch, dummy_result):
    monkeypatch.setenv("SPLUNK_HEC_URL", "http://splunk-server.local:8088/services/collector/event")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "mock-hec-token-uuid")

    forwarder = SplunkForwarder()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"text":"Success","code":0}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        success, msg = forwarder.forward_to_splunk(dummy_result)
        assert success is True
        assert "successfully delivered" in msg.lower()
        mock_post.assert_called_once()


def test_splunk_hec_auth_failure(monkeypatch, dummy_result):
    monkeypatch.setenv("SPLUNK_HEC_URL", "http://splunk-server.local:8088/services/collector/event")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "invalid-token")

    forwarder = SplunkForwarder()

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = '{"text":"Invalid token","code":4}'

    with patch("requests.post", return_value=mock_resp):
        success, msg = forwarder.forward_to_splunk(dummy_result)
        assert success is False
        assert "authentication failed" in msg.lower()


def test_splunk_hec_unconfigured(monkeypatch, dummy_result):
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)

    forwarder = SplunkForwarder()
    success, msg = forwarder.forward_to_splunk(dummy_result)
    assert success is False
    assert "not configured" in msg.lower()
