"""Unit tests for DMARC policy evaluation, record parsing, and alignment conditions."""

from mailguard.dmarc_check import DMARCChecker
from mailguard.models import (
    AuthStatus,
    DKIMResult,
    DKIMSignatureResult,
    ParsedEmail,
    SPFResult,
)
from mailguard.parser import EmailParser


def test_dmarc_pass_via_aligned_spf(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    spf_res = SPFResult(
        status=AuthStatus.PASS,
        identity="alice@example.com",
        domain="example.com",
    )
    dkim_res = DKIMResult(signatures=[], overall_status=AuthStatus.NONE)

    checker = DMARCChecker(resolver=offline_resolver)
    dmarc_res, align_res = checker.evaluate(parsed, spf_res, dkim_res)

    assert dmarc_res.status == AuthStatus.PASS
    assert dmarc_res.spf_aligned_pass is True
    assert dmarc_res.policy == "reject"
    assert align_res.spf_aligned_relaxed is True


def test_dmarc_pass_via_aligned_dkim(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    spf_res = SPFResult(
        status=AuthStatus.FAIL,
        identity="alice@unauthorized.test",
        domain="unauthorized.test",
    )
    dkim_sig = DKIMSignatureResult(
        signing_domain="example.com",
        selector="s1",
        algorithm="rsa-sha256",
        body_hash_status="PASS",
        verification_status=AuthStatus.PASS,
        explanation="Valid",
    )
    dkim_res = DKIMResult(signatures=[dkim_sig], overall_status=AuthStatus.PASS)

    checker = DMARCChecker(resolver=offline_resolver)
    dmarc_res, align_res = checker.evaluate(parsed, spf_res, dkim_res)

    assert dmarc_res.status == AuthStatus.PASS
    assert dmarc_res.dkim_aligned_pass is True
    assert dmarc_res.spf_aligned_pass is False


def test_dmarc_fail_unaligned_and_failing(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.return_path = "attacker@external.test"
    parsed.return_path_domain = "external.test"

    spf_res = SPFResult(
        status=AuthStatus.FAIL,
        identity="attacker@external.test",
        domain="external.test",
    )
    dkim_res = DKIMResult(signatures=[], overall_status=AuthStatus.NONE)

    checker = DMARCChecker(resolver=offline_resolver)
    dmarc_res, _ = checker.evaluate(parsed, spf_res, dkim_res)

    assert dmarc_res.status == AuthStatus.FAIL
    assert dmarc_res.policy == "reject"


def test_dmarc_subdomain_policy_fallback(offline_resolver, sample_email_bytes):
    # Set up org domain with sp=quarantine
    offline_resolver.add_record(
        "_dmarc.example.org",
        "TXT",
        ["v=DMARC1; p=reject; sp=quarantine; pct=100"],
    )

    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.from_address = "alerts@sub.example.org"
    parsed.from_domain = "sub.example.org"

    spf_res = SPFResult(status=AuthStatus.FAIL, identity="sub.example.org", domain="sub.example.org")
    dkim_res = DKIMResult(signatures=[], overall_status=AuthStatus.NONE)

    checker = DMARCChecker(resolver=offline_resolver)
    dmarc_res, _ = checker.evaluate(parsed, spf_res, dkim_res)

    # Effective policy for subdomain should be sp=quarantine
    assert dmarc_res.policy == "quarantine"
    assert dmarc_res.subdomain_policy == "quarantine"


def test_dmarc_none_missing_record(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)
    parsed.from_domain = "norecord.test"

    spf_res = SPFResult(status=AuthStatus.PASS, identity="norecord.test", domain="norecord.test")
    dkim_res = DKIMResult(signatures=[], overall_status=AuthStatus.NONE)

    checker = DMARCChecker(resolver=offline_resolver)
    dmarc_res, _ = checker.evaluate(parsed, spf_res, dkim_res)

    assert dmarc_res.status == AuthStatus.NONE
    assert "No DMARC TXT record found" in dmarc_res.explanation
