"""Synthetic email corpus and offline DNS fixtures generator for MailGuard."""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import json
from pathlib import Path
import time
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import dkim


def generate_rsa_key_pair() -> tuple[bytes, str]:
    """Generate a 2048-bit RSA private key and base64 SubjectPublicKeyInfo string."""
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


def main() -> None:
    base_dir = Path(__file__).resolve().parent.parent
    samples_dir = base_dir / "samples"
    fixtures_dir = base_dir / "tests" / "fixtures"

    (samples_dir / "legit").mkdir(parents=True, exist_ok=True)
    (samples_dir / "suspicious").mkdir(parents=True, exist_ok=True)
    (samples_dir / "spoofed").mkdir(parents=True, exist_ok=True)
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    print("Generating local cryptographic RSA keypair for DKIM signing...")
    priv_pem, pub_b64 = generate_rsa_key_pair()

    # Save private key for testing reuse if needed
    (fixtures_dir / "dkim_test_privkey.pem").write_bytes(priv_pem)

    # --------------------------------------------------------------------------
    # Prepare offline DNS fixture records
    # --------------------------------------------------------------------------
    dns_records: Dict[str, Dict[str, Any]] = {
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
        "paypa1.com": {
            "TXT": ["v=spf1 ip4:198.51.100.50 -all"],
            "A": ["198.51.100.50"],
        },
        "examp1e.com": {
            "TXT": ["v=spf1 +all"],
            "A": ["198.51.100.60"],
        },
        "suspicious-billing.test": {
            "TXT": ["v=spf1 +all"],
            "A": ["198.51.100.70"],
        },
        "attacker-mail.test": {
            "TXT": ["v=spf1 ip4:203.0.113.0/24 -all"],
            "A": ["203.0.113.5"],
        },
        "_dmarc.attacker-mail.test": {
            "TXT": ["v=DMARC1; p=none"],
        },
    }

    fixtures_json_path = fixtures_dir / "dns_records.json"
    fixtures_json_path.write_text(json.dumps(dns_records, indent=2), encoding="utf-8")
    print(f"Wrote offline DNS fixtures to {fixtures_json_path}")

    # ==========================================================================
    # 1. LEGITIMATE SAMPLES
    # ==========================================================================

    # Legit 1: Fully aligned, SPF pass, DKIM pass, DMARC pass
    msg1 = EmailMessage()
    msg1["Received"] = "from mail.example.com ([192.0.2.15]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:00:00 +0000"
    msg1["Message-ID"] = make_msgid(domain="example.com")
    msg1["Date"] = formatdate(localtime=False)
    msg1["From"] = "Alice Security <alice@example.com>"
    msg1["To"] = "soc-team@corp.example.net"
    msg1["Subject"] = "Quarterly Security Metrics Review"
    msg1["Return-Path"] = "<alice@example.com>"
    msg1.set_content("Team,\n\nPlease find the review schedule attached. All authentication controls are functioning normally.\n\nBest,\nAlice")

    raw_bytes1 = msg1.as_bytes()
    sig1 = dkim.sign(raw_bytes1, b"s1", b"example.com", priv_pem)
    (samples_dir / "legit" / "legit_01_standard_auth.eml").write_bytes(sig1 + raw_bytes1)

    # Legit 2: Subdomain relaxed alignment passing DMARC
    msg2 = EmailMessage()
    msg2["Received"] = "from mail.example.com ([192.0.2.22]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:05:00 +0000"
    msg2["Message-ID"] = make_msgid(domain="marketing.example.com")
    msg2["Date"] = formatdate(localtime=False)
    msg2["From"] = "Product Updates <news@marketing.example.com>"
    msg2["To"] = "all-staff@corp.example.net"
    msg2["Subject"] = "Monthly Product Bulletin"
    msg2["Return-Path"] = "<bounces@marketing.example.com>"
    msg2.set_content("Hello everyone,\n\nHere is our monthly engineering newsletter: https://example.com/newsletter\n\nCheers!")

    raw_bytes2 = msg2.as_bytes()
    sig2 = dkim.sign(raw_bytes2, b"s1", b"marketing.example.com", priv_pem)
    (samples_dir / "legit" / "legit_02_subdomain_aligned.eml").write_bytes(sig2 + raw_bytes2)

    # Legit 3: Legitimate business email with PDF attachment
    msg3 = EmailMessage()
    msg3["Received"] = "from mail.example.com ([192.0.2.18]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:10:00 +0000"
    msg3["Message-ID"] = make_msgid(domain="example.com")
    msg3["Date"] = formatdate(localtime=False)
    msg3["From"] = "Finance Department <finance@example.com>"
    msg3["To"] = "accounting@corp.example.net"
    msg3["Subject"] = "Approved Purchase Order PO-9842"
    msg3["Return-Path"] = "<finance@example.com>"
    msg3.set_content("Please find attached the signed purchase order PDF for vendor renewal.\n\nRegards,\nFinance")
    msg3.add_attachment(b"%PDF-1.4 Mock PDF Document Content", maintype="application", subtype="pdf", filename="PO-9842.pdf")

    raw_bytes3 = msg3.as_bytes()
    sig3 = dkim.sign(raw_bytes3, b"s1", b"example.com", priv_pem)
    (samples_dir / "legit" / "legit_03_benign_attachment.eml").write_bytes(sig3 + raw_bytes3)

    # ==========================================================================
    # 2. SUSPICIOUS SAMPLES
    # ==========================================================================

    # Suspicious 1: Reply-To domain mismatch + Urgency prompt
    msg_s1 = EmailMessage()
    msg_s1["Received"] = "from mail.example.com ([192.0.2.19]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:15:00 +0000"
    msg_s1["Message-ID"] = make_msgid(domain="example.com")
    msg_s1["Date"] = formatdate(localtime=False)
    msg_s1["From"] = "Billing Support <billing@example.com>"
    msg_s1["Reply-To"] = "billing-replies@suspicious-billing.test"
    msg_s1["To"] = "victim@corp.example.net"
    msg_s1["Subject"] = "Urgent: Action required on invoice payment update"
    msg_s1["Return-Path"] = "<billing@example.com>"
    msg_s1.set_content("Immediate action required: Please reply directly to confirm your wire transfer routing details to avoid account suspension.\n\nThanks,\nBilling")

    # Leave unsigned so no DKIM (+10), Reply-To mismatch (+15), Urgency (+15) = 40 (SUSPICIOUS)
    (samples_dir / "suspicious" / "suspicious_01_reply_to_mismatch.eml").write_bytes(msg_s1.as_bytes())

    # Suspicious 2: Deceptive URL mismatch (Text says portal.example.com, href points to IP)
    msg_s2 = EmailMessage()
    msg_s2["Received"] = "from mail.example.com ([192.0.2.20]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:20:00 +0000"
    msg_s2["Message-ID"] = make_msgid(domain="example.com")
    msg_s2["Date"] = formatdate(localtime=False)
    msg_s2["From"] = "Corporate IT <it-help@example.com>"
    msg_s2["To"] = "staff@corp.example.net"
    msg_s2["Subject"] = "Scheduled portal maintenance and migration"
    msg_s2["Return-Path"] = "<it-help@example.com>"
    html_s2 = """<html><body>
    <p>Please log in to verify your profile settings:</p>
    <p><a href="http://198.51.100.88/login">https://portal.example.com/sso</a></p>
    </body></html>"""
    msg_s2.set_content("Please log in to verify your profile settings at https://portal.example.com/sso")
    msg_s2.add_alternative(html_s2, subtype="html")

    raw_bytes_s2 = msg_s2.as_bytes()
    sig_s2 = dkim.sign(raw_bytes_s2, b"s1", b"example.com", priv_pem)
    (samples_dir / "suspicious" / "suspicious_02_url_mismatch.eml").write_bytes(sig_s2 + raw_bytes_s2)

    # Suspicious 3: Urgency language + URL shortener without DKIM signature
    msg_s3 = EmailMessage()
    msg_s3["Received"] = "from mail.example.com ([192.0.2.21]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:25:00 +0000"
    msg_s3["Message-ID"] = make_msgid(domain="example.com")
    msg_s3["Date"] = formatdate(localtime=False)
    msg_s3["From"] = "Admin <alerts@example.com>"
    msg_s3["To"] = "user@corp.example.net"
    msg_s3["Subject"] = "Urgent: Account suspended due to unauthorized access"
    msg_s3["Return-Path"] = "<alerts@example.com>"
    msg_s3.set_content("Immediate action required: verify your account credentials immediately at https://bit.ly/secure-auth to avoid suspension.")

    # Unsigned: missing DKIM (+10) + Urgency (+15) + Shortener (+10) = 35 (SUSPICIOUS)
    (samples_dir / "suspicious" / "suspicious_03_urgency_shortener.eml").write_bytes(msg_s3.as_bytes())

    # Suspicious 4: Missing Message-ID & Suspicious TLD
    msg_s4 = EmailMessage()
    msg_s4["Received"] = "from mail.example.com ([192.0.2.25]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:30:00 +0000"
    msg_s4["Date"] = formatdate(localtime=False)
    msg_s4["From"] = "Customer Survey <survey@rewards.top>"
    msg_s4["To"] = "user@corp.example.net"
    msg_s4["Subject"] = "Claim your $50 gift card reward"
    msg_s4["Return-Path"] = "<survey@rewards.top>"
    msg_s4.set_content("Click here to complete your feedback: http://rewards.top/claim")
    (samples_dir / "suspicious" / "suspicious_04_missing_msgid_tld.eml").write_bytes(msg_s4.as_bytes())

    # ==========================================================================
    # 3. SPOOFED SAMPLES
    # ==========================================================================

    # Spoofed 1: Direct domain spoofing (From example.com from unauthorized IP 198.51.100.99, SPF fail, no DKIM, DMARC fail)
    msg_sp1 = EmailMessage()
    msg_sp1["Received"] = "from evil-mta.test ([198.51.100.99]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:35:00 +0000"
    msg_sp1["Message-ID"] = make_msgid(domain="example.com")
    msg_sp1["Date"] = formatdate(localtime=False)
    msg_sp1["From"] = "Security Operations <security@example.com>"
    msg_sp1["To"] = "executives@corp.example.net"
    msg_sp1["Subject"] = "Mandatory MFA Enrollment - Action Required"
    msg_sp1["Return-Path"] = "<security@example.com>"
    msg_sp1.set_content("Security notice: You must enroll your mobile authenticator at http://198.51.100.99/mfa")
    (samples_dir / "spoofed" / "spoofed_01_spf_dmarc_fail.eml").write_bytes(msg_sp1.as_bytes())

    # Spoofed 2: Typosquatting lookalike domain (paypa1.com with urgent account suspension)
    msg_sp2 = EmailMessage()
    msg_sp2["Received"] = "from out.paypa1.com ([198.51.100.50]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:40:00 +0000"
    msg_sp2["Message-ID"] = make_msgid(domain="paypa1.com")
    msg_sp2["Date"] = formatdate(localtime=False)
    msg_sp2["From"] = "PayPal Support <service@paypa1.com>"
    msg_sp2["To"] = "target@corp.example.net"
    msg_sp2["Subject"] = "Urgent: Your PayPal account has been limited"
    msg_sp2["Return-Path"] = "<service@paypa1.com>"
    msg_sp2.set_content("Unauthorized transaction detected. Immediate action required to verify your account: http://paypa1.com/verify")
    (samples_dir / "spoofed" / "spoofed_02_lookalike_typosquatting.eml").write_bytes(msg_sp2.as_bytes())

    # Spoofed 3: Double extension attachment + Display name spoofing
    msg_sp3 = EmailMessage()
    msg_sp3["Received"] = "from mail.attacker-mail.test ([203.0.113.5]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:45:00 +0000"
    msg_sp3["Message-ID"] = make_msgid(domain="attacker-mail.test")
    msg_sp3["Date"] = formatdate(localtime=False)
    msg_sp3["From"] = '"Helpdesk <admin@example.com>" <hacker@attacker-mail.test>'
    msg_sp3["To"] = "employee@corp.example.net"
    msg_sp3["Subject"] = "Critical Security Patch Update"
    msg_sp3["Return-Path"] = "<hacker@attacker-mail.test>"
    msg_sp3.set_content("Please run the attached patch to fix vulnerability CVE-2026-9999.")
    msg_sp3.add_attachment(b"MZ\x90\x00BinaryMockPayload", maintype="application", subtype="octet-stream", filename="SecurityPatch_v2.1.pdf.exe")
    (samples_dir / "spoofed" / "spoofed_03_double_extension_display_spoof.eml").write_bytes(msg_sp3.as_bytes())

    # Spoofed 4: Tampered DKIM signature (DKIM verification fail)
    msg_sp4 = EmailMessage()
    msg_sp4["Received"] = "from spoof.attacker-mail.test ([203.0.113.99]) by inbound.security.local with ESMTP; Wed, 28 Oct 2026 10:50:00 +0000"
    msg_sp4["Message-ID"] = make_msgid(domain="example.com")
    msg_sp4["Date"] = formatdate(localtime=False)
    msg_sp4["From"] = "CEO Office <ceo@example.com>"
    msg_sp4["To"] = "cfo@corp.example.net"
    msg_sp4["Subject"] = "Confidential Wire Transfer Request"
    msg_sp4["Return-Path"] = "<ceo@example.com>"
    msg_sp4.set_content("Original content before tampering.")

    # Sign then alter body to force cryptographic DKIM and body-hash failure
    raw_sp4 = msg_sp4.as_bytes()
    sig_sp4 = dkim.sign(raw_sp4, b"s1", b"example.com", priv_pem)
    tampered_body = raw_sp4 + b"\r\nURGENT: Wire $250,000 immediately to account 987654321."
    (samples_dir / "spoofed" / "spoofed_04_tampered_dkim_signature.eml").write_bytes(sig_sp4 + tampered_body)

    print("Successfully generated all synthetic email samples in samples/{legit,suspicious,spoofed}!")


if __name__ == "__main__":
    main()
