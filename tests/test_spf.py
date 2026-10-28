"""Unit tests for SPF evaluation using pyspf and offline fixtures."""

from mailguard.models import AuthStatus, ParsedEmail
from mailguard.parser import EmailParser
from mailguard.spf_check import SPFChecker


def test_spf_pass_authorized_ip(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    checker = SPFChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.status == AuthStatus.PASS
    assert result.domain == "example.com"
    assert "authorized" in result.explanation.lower()


def test_spf_fail_unauthorized_ip(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    # Alter originating IP to unlisted external IP
    parsed.candidate_originating_ip = "198.51.100.99"

    checker = SPFChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.status == AuthStatus.FAIL
    assert result.domain == "example.com"


def test_spf_softfail(offline_resolver, sample_email_bytes):
    # Add a domain with ~all
    offline_resolver.add_record("softfail.test", "TXT", ["v=spf1 ip4:192.0.2.1 ~all"])
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.return_path = "user@softfail.test"
    parsed.return_path_domain = "softfail.test"
    parsed.candidate_originating_ip = "198.51.100.5"

    checker = SPFChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.status == AuthStatus.SOFTFAIL


def test_spf_none_no_record(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.return_path = "user@nodns.test"
    parsed.return_path_domain = "nodns.test"

    checker = SPFChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.status == AuthStatus.NONE


def test_spf_fallback_auth_results_header(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.candidate_originating_ip = None
    parsed.auth_results_headers = ["mail.example.com; spf=pass smtp.mailfrom=example.com"]

    checker = SPFChecker(resolver=offline_resolver, trusted_receivers=["mail.example.com"])
    result = checker.evaluate(parsed)

    assert result.status == AuthStatus.PASS
    assert "Authentication-Results" in result.explanation
