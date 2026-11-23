"""Unit tests for the Flask Web interface and security protections."""

import io
import pytest

from mailguard.web import create_app


@pytest.fixture
def client():
    app = create_app(offline=True)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_web_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"MailGuard SOC Email Analyzer" in resp.data
    # Verify security headers
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers


def test_web_upload_valid_eml(client, sample_email_bytes):
    # Retrieve session CSRF token first
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(sample_email_bytes), "test_upload.eml"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Authentication Framework" in resp.data
    assert b"LEGITIMATE" in resp.data


def test_web_upload_invalid_extension(client):
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(b"fake content"), "malicious.exe"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert b"Only .eml files are accepted" in resp.data


def test_web_upload_csrf_protection(client, sample_email_bytes):
    # Attempt upload with invalid CSRF token
    data = {
        "csrf_token": "invalid_forged_csrf_token",
        "email_file": (io.BytesIO(sample_email_bytes), "test.eml"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 403
    assert b"Invalid or expired CSRF token" in resp.data


def test_web_download_json_after_upload(client, sample_email_bytes):
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(sample_email_bytes), "test_download.eml"),
    }
    client.post("/upload", data=data, content_type="multipart/form-data")

    dl_resp = client.get("/download/json")
    assert dl_resp.status_code == 200
    assert dl_resp.mimetype == "application/json"
    assert b'"verdict": "LEGITIMATE"' in dl_resp.data


def test_web_upload_oversize(client):
    # Test uploading content that exceeds MAX_CONTENT_LENGTH
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    # MAX_CONTENT_LENGTH is 25MB, simulate oversize payload error
    oversized_data = b"X" * (26 * 1024 * 1024)
    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(oversized_data), "huge.eml"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 413


def test_web_upload_malformed_email(client):
    # Test uploading a corrupted or malformed byte stream
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    malformed_bytes = b"Subject: =?UTF-8?B?invalid-base64???\r\nFrom: <bad\r\n\r\nCorrupted text\x00\xff"
    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(malformed_bytes), "malformed.eml"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    # Should safely process and return 200 without 500 server crash
    assert resp.status_code == 200
    assert b"MailGuard" in resp.data


def test_web_html_escaping(client):
    # Test XSS payload in Subject/From is safely escaped
    resp_init = client.get("/")
    with client.session_transaction() as sess:
        csrf_tok = sess.get("csrf_token")

    xss_email = (
        b"From: \"<script>alert('xss')</script>\" <attacker@example.com>\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: <img src=x onerror=alert(1)>\r\n"
        b"Date: Wed, 28 Oct 2026 10:00:00 +0000\r\n"
        b"Message-ID: <xss-test@example.com>\r\n"
        b"\r\n"
        b"Hello world\r\n"
    )
    data = {
        "csrf_token": csrf_tok,
        "email_file": (io.BytesIO(xss_email), "xss.eml"),
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    # Must NOT contain raw unescaped script tag or onerror
    assert b"<script>alert('xss')</script>" not in resp.data
    assert b"<img src=x onerror=alert(1)>" not in resp.data
    # Must contain HTML escaped representation
    assert b"&lt;script&gt;" in resp.data or b"&lt;img" in resp.data

