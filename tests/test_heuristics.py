"""Unit tests for the 17 heuristic detection rules."""

from email.message import EmailMessage

from mailguard.heuristics import HeuristicEngine
from mailguard.parser import EmailParser


def test_heuristic_reply_to_mismatch():
    msg = EmailMessage()
    msg["From"] = "help@legit.com"
    msg["Reply-To"] = "collector@external-drop.net"
    msg["Subject"] = "Hello"
    msg.set_content("Test body")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-REPLYTO-MISMATCH" for h in findings)


def test_heuristic_display_name_spoof():
    msg = EmailMessage()
    msg["From"] = '"PayPal Support <support@paypal.com>" <hacker@evil.com>'
    msg["Subject"] = "Update"
    msg.set_content("Please verify")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-DISPLAY-NAME-SPOOF" for h in findings)


def test_heuristic_lookalike_domain():
    msg = EmailMessage()
    msg["From"] = "service@paypa1.com"
    msg["Subject"] = "Account update"
    msg.set_content("Details inside")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-LOOKALIKE-DOMAIN" for h in findings)


def test_heuristic_unicode_punycode():
    msg = EmailMessage()
    msg["From"] = "security@xn--pple-43d.com"
    msg["Subject"] = "Apple alert"
    msg.set_content("Test")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-UNICODE-PUNYCODE" for h in findings)


def test_heuristic_suspicious_tld():
    msg = EmailMessage()
    msg["From"] = "updates@system.zip"
    msg["Subject"] = "File update"
    msg.set_content("Test")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-SUSPICIOUS-TLD" for h in findings)


def test_heuristic_urgency_keywords():
    msg = EmailMessage()
    msg["From"] = "info@example.com"
    msg["Subject"] = "Urgent: Immediate action required"
    msg.set_content("Your account will be suspended indefinitely unless you verify now.")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-URGENCY-LANGUAGE" for h in findings)


def test_heuristic_double_extension_attachment():
    msg = EmailMessage()
    msg["From"] = "billing@example.com"
    msg["Subject"] = "Invoice"
    msg.set_content("Invoice attached")
    msg.add_attachment(b"binary_code", maintype="application", subtype="octet-stream", filename="Document.pdf.vbs")

    parser = EmailParser()
    parsed = parser.parse_bytes(msg.as_bytes())

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    assert any(h.id == "HEUR-DOUBLE-EXTENSION" for h in findings)
    assert any(h.id == "HEUR-RISKY-ATTACHMENT" for h in findings)


def test_heuristic_clean_email_zero_findings(sample_email_bytes):
    parser = EmailParser()
    parsed = parser.parse_bytes(sample_email_bytes)

    engine = HeuristicEngine()
    findings = engine.analyze(parsed)

    # Benign corporate email should not trigger false positives
    assert len(findings) == 0
