"""Pytest fixtures for MailGuard test suite."""

import base64
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import json
from pathlib import Path
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mailguard.dns_resolver import OfflineDNSResolver
from mailguard.utils import load_config


@pytest.fixture(scope="session")
def test_config():
    """Load default configuration for tests."""
    return load_config()


@pytest.fixture(scope="session")
def rsa_keypair():
    """Generate a valid RSA keypair for cryptographic DKIM test fixtures."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return priv_pem, pub_b64


@pytest.fixture
def offline_resolver(rsa_keypair):
    """Provide an OfflineDNSResolver with standard test fixtures loaded."""
    _, pub_b64 = rsa_keypair
    fixtures = {
        "example.com": {
            "TXT": ["v=spf1 ip4:192.0.2.0/24 -all"],
            "A": ["192.0.2.10"],
            "MX": [[10, "mail.example.com"]],
        },
        "mail.example.com": {
            "A": ["192.0.2.1"],
        },
        "_dmarc.example.com": {
            "TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; adkim=r; aspf=r"],
        },
        "s1._domainkey.example.com": {
            "TXT": [f"v=DKIM1; k=rsa; p={pub_b64}"],
        },
        "marketing.example.com": {
            "TXT": ["v=spf1 ip4:192.0.2.0/24 -all"],
            "A": ["192.0.2.20"],
        },
        "s1._domainkey.marketing.example.com": {
            "TXT": [f"v=DKIM1; k=rsa; p={pub_b64}"],
        },
        "corp.example.net": {
            "TXT": ["v=spf1 ip4:192.0.2.0/24 -all"],
            "A": ["192.0.2.30"],
        },
        "_dmarc.corp.example.net": {
            "TXT": ["v=DMARC1; p=quarantine; pct=100; rua=mailto:reports@corp.example.net"],
        },
        "s1._domainkey.corp.example.net": {
            "TXT": [f"v=DKIM1; k=rsa; p={pub_b64}"],
        },
    }
    return OfflineDNSResolver(fixtures=fixtures)


@pytest.fixture
def sample_email_bytes():
    """Create a basic RFC 5322 MIME email message."""
    msg = EmailMessage()
    msg["Received"] = "from mail.example.com ([192.0.2.15]) by inbound.security.local; Wed, 28 Oct 2026 10:00:00 +0000"
    msg["Message-ID"] = make_msgid(domain="example.com")
    msg["Date"] = formatdate(localtime=False)
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@corp.example.net>"
    msg["Subject"] = "Test Subject"
    msg["Return-Path"] = "<alice@example.com>"
    msg.set_content("Hello Bob,\nThis is a clean test message.\nhttps://example.com/welcome")
    return msg.as_bytes()
