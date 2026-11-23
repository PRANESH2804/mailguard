"""Unit tests for MIME parser, URL extraction, attachment inspection, and originating IP extraction."""

from email.message import EmailMessage
import pytest

from mailguard.parser import EmailParser


def test_parser_basic_headers(sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    assert parsed.from_address == "alice@example.com"
    assert parsed.from_domain == "example.com"
    assert parsed.return_path == "alice@example.com"
    assert parsed.subject == "Test Subject"
    assert "bob@corp.example.net" in parsed.to_addresses
    assert parsed.candidate_originating_ip == "192.0.2.15"


def test_parser_mime_encoded_subject():
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["Subject"] = "=?UTF-8?B?U2VjdXJpdHkgQWxlcnQh?="  # "Security Alert!"
    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    assert parsed.subject == "Security Alert!"


def test_parser_url_extraction_plain_and_html():
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["Subject"] = "URL Test"
    msg.set_content("Visit https://example.com/login for details.")
    html_content = """<html><body>
        <p><a href="http://198.51.100.99/phish">Click Here</a></p>
        <p><a href="http://evil.com/login">https://paypal.com/verify</a></p>
    </body></html>"""
    msg.add_alternative(html_content, subtype="html")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    assert len(parsed.urls) >= 2
    # Check text-vs-href mismatch
    mismatch_url = next((u for u in parsed.urls if u.domain_mismatch), None)
    assert mismatch_url is not None
    assert mismatch_url.domain == "evil.com"
    assert "paypal.com" in mismatch_url.visible_text


def test_parser_attachment_hashing_and_risky_extension():
    msg = EmailMessage()
    msg["From"] = "attacker@evil.com"
    msg["Subject"] = "Invoice"
    msg.set_content("Please see attached invoice.")
    # Add double extension attachment
    payload_data = b"MOCK_MALICIOUS_EXECUTABLE_CONTENT"
    msg.add_attachment(
        payload_data,
        maintype="application",
        subtype="octet-stream",
        filename="Invoice_2026.pdf.exe",
    )

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Invoice_2026.pdf.exe"
    assert att.is_double_extension is True
    assert att.is_risky is True
    assert ".exe" in att.detected_extensions
    assert len(att.sha256) == 64


def test_parser_missing_message_id_anomaly():
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "No Message-ID"
    msg.set_content("Missing message ID header.")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    assert any(a.header_name == "Message-ID" for a in parsed.header_anomalies)


def test_parser_max_size_limit():
    parser = EmailParser()
    parser.max_message_bytes = 100  # Set artificially low limit
    with pytest.raises(ValueError, match="exceeds maximum"):
        parser.parse_bytes(b"A" * 200)


def test_parser_originating_ip_received_chain_boundary():
    # Chain: sender (203.0.113.50) -> trusted gateway (192.0.2.1) -> internal receiver (10.0.0.5)
    raw = (
        b"From: test@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Boundary Test\r\n"
        b"Message-ID: <boundary@example.com>\r\n"
        b"Received: from internal.corp.local ([10.0.0.5]) by mail.corp.local with ESMTP; Wed, 28 Oct 2026 10:02:00 +0000\r\n"
        b"Received: from gateway.corp.example.com ([192.0.2.1]) by internal.corp.local with ESMTP; Wed, 28 Oct 2026 10:01:00 +0000\r\n"
        b"Received: from remote.sender.net ([203.0.113.50]) by gateway.corp.example.com with ESMTP; Wed, 28 Oct 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Test body\r\n"
    )
    parser = EmailParser(config={"trusted_receivers": ["gateway.corp.example.com", "mail.corp.local"]})
    parsed = parser.parse_bytes(raw)
    assert parsed.candidate_originating_ip == "203.0.113.50"

