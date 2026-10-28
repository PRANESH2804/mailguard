"""Unit tests for DKIM cryptographic signature verification using dkimpy and test RSA keys."""

import time
import dkim
import pytest

from mailguard.dkim_check import DKIMChecker
from mailguard.models import AuthStatus
from mailguard.parser import EmailParser


def test_dkim_valid_signature(rsa_keypair, offline_resolver, sample_email_bytes):
    priv_pem, _ = rsa_keypair
    sig = dkim.sign(sample_email_bytes, b"s1", b"example.com", priv_pem)
    signed_bytes = sig + sample_email_bytes

    parser = EmailParser()
    parsed = parser.parse_bytes(signed_bytes)

    checker = DKIMChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.overall_status == AuthStatus.PASS
    assert len(result.signatures) == 1
    assert result.signatures[0].signing_domain == "example.com"
    assert result.signatures[0].verification_status == AuthStatus.PASS
    assert result.signatures[0].body_hash_status == "PASS"


def test_dkim_tampered_body_hash_mismatch(rsa_keypair, offline_resolver, sample_email_bytes):
    priv_pem, _ = rsa_keypair
    sig = dkim.sign(sample_email_bytes, b"s1", b"example.com", priv_pem)
    # Alter body after signing
    tampered_bytes = sig + sample_email_bytes + b"\r\nTAMPERED_CONTENT_ATTACK"

    parser = EmailParser()
    parsed = parser.parse_bytes(tampered_bytes)

    checker = DKIMChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.overall_status == AuthStatus.FAIL
    assert result.signatures[0].body_hash_status == "FAIL"
    assert "body hash mismatch" in result.signatures[0].explanation.lower()


def test_dkim_missing_public_key(rsa_keypair, offline_resolver, sample_email_bytes):
    priv_pem, _ = rsa_keypair
    # Sign with unknown selector
    sig = dkim.sign(sample_email_bytes, b"unknown_selector", b"example.com", priv_pem)
    signed_bytes = sig + sample_email_bytes

    parser = EmailParser()
    parsed = parser.parse_bytes(signed_bytes)

    checker = DKIMChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.overall_status == AuthStatus.FAIL
    assert result.signatures[0].verification_status == AuthStatus.PERMERROR
    assert "not found" in result.signatures[0].explanation.lower()


def test_dkim_no_signature(offline_resolver, sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    checker = DKIMChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.overall_status == AuthStatus.NONE
    assert len(result.signatures) == 0


def test_dkim_expired_signature(rsa_keypair, offline_resolver, sample_email_bytes):
    priv_pem, _ = rsa_keypair
    now = int(time.time())
    past_t = now - 200
    past_x = now - 100
    sig = dkim.sign(
        sample_email_bytes,
        b"s1",
        b"example.com",
        priv_pem,
        include_headers=[b"from", b"subject", b"date"],
    )
    # Inject valid ordering t=past_t; x=past_x;
    import re
    sig_modified = re.sub(rb"t=\d+;", f"t={past_t}; x={past_x};".encode("ascii"), sig)
    signed_bytes = sig_modified + sample_email_bytes

    parser = EmailParser()
    parsed = parser.parse_bytes(signed_bytes)

    checker = DKIMChecker(resolver=offline_resolver)
    result = checker.evaluate(parsed)

    assert result.signatures[0].verification_status == AuthStatus.FAIL
    assert "expired" in result.signatures[0].explanation.lower()
