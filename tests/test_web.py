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
