"""Unit tests for optional threat intelligence enrichment module."""

from unittest.mock import MagicMock, patch
import pytest

from mailguard.enrichment import ThreatEnricher


def test_enrichment_disabled_by_default():
    enricher = ThreatEnricher()
    assert enricher.is_configured() is False
    assert enricher.lookup_ip("192.0.2.1") is None
    assert enricher.lookup_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None


def test_enrichment_abuseipdb_mocked(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "mock_key_12345")
    enricher = ThreatEnricher()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.99",
            "abuseConfidenceScore": 85,
            "totalReports": 42,
        }
    }

    with patch("requests.get", return_value=mock_resp):
        res = enricher.lookup_ip("198.51.100.99")
        assert res is not None
        assert res.verdict == "MALICIOUS"
        assert res.score == 85
        assert res.provider == "AbuseIPDB"

        # Verify caching (requests.get should not be called again)
        with patch("requests.get") as second_call:
            cached_res = enricher.lookup_ip("198.51.100.99")
            assert cached_res == res
            second_call.assert_not_called()


def test_enrichment_virustotal_mocked(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "mock_vt_key")
    enricher = ThreatEnricher()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 2,
                    "undetected": 55,
                    "harmless": 0,
                }
            }
        }
    }

    test_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    with patch("requests.get", return_value=mock_resp):
        res = enricher.lookup_file_hash(test_hash)
        assert res is not None
        assert res.verdict == "MALICIOUS"
        assert res.malicious_votes == 12
