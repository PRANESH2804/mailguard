"""Unit tests for SPF and DKIM domain identifier alignment logic."""

from mailguard.alignment import IdentifierAlignment


def test_alignment_exact_match():
    align = IdentifierAlignment()
    res = align.evaluate(
        visible_from_domain="example.com",
        spf_domain="example.com",
        dkim_domains=["example.com"],
    )
    assert res.spf_aligned_strict is True
    assert res.spf_aligned_relaxed is True
    assert res.dkim_aligned_strict is True
    assert res.dkim_aligned_relaxed is True


def test_alignment_subdomain_relaxed():
    align = IdentifierAlignment()
    res = align.evaluate(
        visible_from_domain="marketing.example.com",
        spf_domain="example.com",
        dkim_domains=["example.com"],
    )
    # Different FQDN -> Strict is False
    assert res.spf_aligned_strict is False
    assert res.dkim_aligned_strict is False
    # Same organizational domain -> Relaxed is True
    assert res.spf_aligned_relaxed is True
    assert res.dkim_aligned_relaxed is True


def test_alignment_unrelated_domains():
    align = IdentifierAlignment()
    res = align.evaluate(
        visible_from_domain="legit-corp.com",
        spf_domain="attacker-relay.net",
        dkim_domains=["unrelated-host.org"],
    )
    assert res.spf_aligned_strict is False
    assert res.spf_aligned_relaxed is False
    assert res.dkim_aligned_strict is False
    assert res.dkim_aligned_relaxed is False


def test_alignment_public_suffix_co_uk():
    align = IdentifierAlignment()
    res = align.evaluate(
        visible_from_domain="sub.company.co.uk",
        spf_domain="company.co.uk",
        dkim_domains=["company.co.uk"],
    )
    assert res.spf_aligned_strict is False
    assert res.spf_aligned_relaxed is True
    assert res.dkim_aligned_relaxed is True
