"""Flask Web interface providing a professional, SOC-oriented defensive email analyzer."""

from __future__ import annotations

import io
import json
import logging
import os
import secrets
from typing import Any, Dict, Optional

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

from mailguard.cli import MailGuardAnalyzer
from mailguard.models import AnalysisResult
from mailguard.utils import load_config, safe_html

logger = logging.getLogger(__name__)

# Modern, secure SOC Dashboard Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailGuard | Email Authentication & Spoofing Analyzer</title>
    <style>
        :root {
            --bg-dark: #0a0f1d;
            --card-bg: #11192e;
            --border-color: #1e293b;
            --primary: #38bdf8;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --legit: #10b981;
            --suspicious: #f59e0b;
            --spoofed: #ef4444;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .header h1 { margin: 0; font-size: 1.6rem; color: var(--primary); }
        .upload-card {
            background: var(--card-bg);
            border: 2px dashed var(--border-color);
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            margin-bottom: 30px;
        }
        .upload-card:hover { border-color: var(--primary); }
        .btn {
            background: #0284c7;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.2s;
        }
        .btn:hover { background: #0369a1; }
        .file-input { margin: 12px 0; }
        .card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85rem;
        }
        .badge-legitimate { background: rgba(16, 185, 129, 0.2); color: var(--legit); border: 1px solid var(--legit); }
        .badge-suspicious { background: rgba(245, 158, 11, 0.2); color: var(--suspicious); border: 1px solid var(--suspicious); }
        .badge-spoofed { background: rgba(239, 68, 68, 0.2); color: var(--spoofed); border: 1px solid var(--spoofed); }
        .badge-pass { background: rgba(16, 185, 129, 0.2); color: var(--legit); }
        .badge-fail { background: rgba(239, 68, 68, 0.2); color: var(--spoofed); }
        .badge-warn { background: rgba(245, 158, 11, 0.2); color: var(--suspicious); }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-dim); text-transform: uppercase; font-size: 0.75rem; }
        code { background: #080c16; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: var(--primary); }
        .alert-error {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            border: 1px solid var(--spoofed);
        }
        .progress-bar-bg { background: #1e293b; height: 10px; border-radius: 5px; overflow: hidden; margin-top: 6px; }
        .progress-bar-fill { height: 100%; }
        .fill-legitimate { background: var(--legit); }
        .fill-suspicious { background: var(--suspicious); }
        .fill-spoofed { background: var(--spoofed); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ MailGuard SOC Email Analyzer</h1>
                <p style="margin: 4px 0 0 0; color: var(--text-dim); font-size: 0.9rem;">
                    Defensive Email Authentication (SPF, DKIM, DMARC), Heuristic Spoofing Detection & Splunk Forwarding
                </p>
            </div>
            <div>
                <span style="font-size: 0.85rem; color: var(--text-dim);">Status: <strong>Active (Localhost)</strong></span>
            </div>
        </div>

        {% if error %}
        <div class="alert-error">
            <strong>Error:</strong> {{ error }}
        </div>
        {% endif %}

        <div class="upload-card">
            <h3 style="margin: 0 0 8px 0;">Analyze Raw Email File (.eml)</h3>
            <p style="color: var(--text-dim); margin: 0 0 16px 0; font-size: 0.9rem;">
                Select an RFC 5322 MIME .eml message to perform complete authentication verification and spoofing analysis.
            </p>
            <form action="{{ url_for('upload') }}" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="file" name="email_file" accept=".eml" required class="file-input"><br>
                <button type="submit" class="btn">Analyze Message</button>
            </form>
        </div>

        {% if result %}
        <div class="card" style="border-left: 6px solid {% if result.verdict == 'LEGITIMATE' %}var(--legit){% elif result.verdict == 'SUSPICIOUS' %}var(--suspicious){% else %}var(--spoofed){% endif %};">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <h2 style="margin: 0 0 6px 0;">{{ result.subject }}</h2>
                    <p style="margin: 0; color: var(--text-dim); font-size: 0.9rem;">
                        From: <code>{{ result.from_address }}</code> | Return-Path: <code>{{ result.return_path or 'None' }}</code> | Originating IP: <code>{{ result.originating_ip or 'Undetermined' }}</code>
                    </p>
                    <p style="margin: 4px 0 0 0; color: var(--text-dim); font-size: 0.85rem;">
                        Message-ID: <code>{{ result.message_id or 'Missing' }}</code>
                    </p>
                </div>
                <div style="text-align: right; min-width: 180px;">
                    <div class="badge badge-{{ result.verdict.lower() }}">{{ result.verdict }}</div>
                    <div style="margin-top: 8px; font-size: 0.9rem;">Risk Score: <strong>{{ result.risk_score }} / 100</strong></div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill fill-{{ result.verdict.lower() }}" style="width: {{ result.risk_score }}%;"></div>
                    </div>
                    <div style="margin-top: 10px;">
                        <a href="{{ url_for('download_json') }}" class="btn" style="padding: 4px 10px; font-size: 0.75rem; text-decoration: none;">Export JSON</a>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h3 style="margin-top: 0;">Authentication Framework</h3>
                <table>
                    <thead>
                        <tr><th>Check</th><th>Status</th><th>Evaluated Identity</th><th>Details</th></tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>SPF</strong></td>
                            <td><span class="badge badge-{{ 'pass' if result.spf.status == 'PASS' else ('warn' if result.spf.status in ('SOFTFAIL', 'NEUTRAL') else 'fail') }}">{{ result.spf.status }}</span></td>
                            <td><code>{{ result.spf.domain }}</code></td>
                            <td>{{ result.spf.explanation }}</td>
                        </tr>
                        <tr>
                            <td><strong>DKIM</strong></td>
                            <td><span class="badge badge-{{ 'pass' if result.dkim.overall_status == 'PASS' else 'fail' }}">{{ result.dkim.overall_status }}</span></td>
                            <td><code>{{ result.dkim.signatures[0].signing_domain if result.dkim.signatures else 'None' }}</code></td>
                            <td>{{ result.dkim.explanation }}</td>
                        </tr>
                        <tr>
                            <td><strong>DMARC</strong></td>
                            <td><span class="badge badge-{{ 'pass' if result.dmarc.status == 'PASS' else 'fail' }}">{{ result.dmarc.status }}</span></td>
                            <td><code>policy={{ result.dmarc.policy }}</code></td>
                            <td>{{ result.dmarc.explanation }}</td>
                        </tr>
                    </tbody>
                </table>

                <h4 style="margin: 16px 0 8px 0;">Identifier Alignment</h4>
                <table>
                    <tbody>
                        <tr>
                            <td>SPF Alignment</td>
                            <td><span class="badge badge-{{ 'pass' if result.alignment.spf_aligned_relaxed else 'fail' }}">{{ 'PASS' if result.alignment.spf_aligned_relaxed else 'FAIL' }}</span></td>
                            <td>Strict: {{ result.alignment.spf_aligned_strict }} | Relaxed: {{ result.alignment.spf_aligned_relaxed }}</td>
                        </tr>
                        <tr>
                            <td>DKIM Alignment</td>
                            <td><span class="badge badge-{{ 'pass' if result.alignment.dkim_aligned_relaxed else 'fail' }}">{{ 'PASS' if result.alignment.dkim_aligned_relaxed else 'FAIL' }}</span></td>
                            <td>Strict: {{ result.alignment.dkim_aligned_strict }} | Relaxed: {{ result.alignment.dkim_aligned_relaxed }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h3 style="margin-top: 0;">Risk Analysis & Top Contributors</h3>
                <ul style="padding-left: 20px; line-height: 1.6;">
                    {% for reason in result.top_reasons %}
                    <li>{{ reason }}</li>
                    {% endfor %}
                </ul>

                {% if result.mitre_techniques %}
                <h4 style="margin: 16px 0 8px 0;">MITRE ATT&CK Mappings</h4>
                <table>
                    <thead>
                        <tr><th>ID</th><th>Technique</th><th>Tactic</th></tr>
                    </thead>
                    <tbody>
                        {% for m in result.mitre_techniques %}
                        <tr>
                            <td><code>{{ m.technique_id }}</code></td>
                            <td><strong>{{ m.technique_name }}</strong></td>
                            <td>{{ m.tactic }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
            </div>
        </div>

        {% if result.heuristics %}
        <div class="card">
            <h3 style="margin-top: 0;">Heuristic Risk Indicators ({{ result.heuristics|length }})</h3>
            <table>
                <thead>
                    <tr><th>Rule ID</th><th>Severity</th><th>Weight</th><th>Name & Evidence</th></tr>
                </thead>
                <tbody>
                    {% for h in result.heuristics %}
                    <tr>
                        <td><code>{{ h.id }}</code></td>
                        <td><span class="badge badge-{{ 'fail' if h.severity in ('CRITICAL', 'HIGH') else ('warn' if h.severity == 'MEDIUM' else 'pass') }}">{{ h.severity }}</span></td>
                        <td>+{{ h.weight }}</td>
                        <td><strong>{{ h.name }}</strong><br><small style="color: var(--text-dim);">{{ h.evidence }}</small></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if result.attachments %}
        <div class="card">
            <h3 style="margin-top: 0;">Extracted Attachments ({{ result.attachments|length }})</h3>
            <table>
                <thead>
                    <tr><th>Filename</th><th>MIME Type</th><th>Size</th><th>SHA-256</th><th>Status</th></tr>
                </thead>
                <tbody>
                    {% for a in result.attachments %}
                    <tr>
                        <td><code>{{ a.filename }}</code></td>
                        <td>{{ a.content_type }}</td>
                        <td>{{ a.size_bytes }} B</td>
                        <td><code>{{ a.sha256[:24] }}...</code></td>
                        <td><span class="badge badge-{{ 'fail' if (a.is_risky or a.is_double_extension) else 'pass' }}">{{ 'RISKY' if (a.is_risky or a.is_double_extension) else 'BENIGN' }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if result.urls %}
        <div class="card">
            <h3 style="margin-top: 0;">Extracted URLs ({{ result.urls|length }})</h3>
            <table>
                <thead>
                    <tr><th>Destination Domain</th><th>Scheme</th><th>Indicators</th><th>Destination URL</th></tr>
                </thead>
                <tbody>
                    {% for u in result.urls %}
                    <tr>
                        <td><code>{{ u.domain }}</code></td>
                        <td>{{ u.scheme }}</td>
                        <td>
                            {% if u.domain_mismatch %}<span class="badge badge-fail">Mismatch</span>{% endif %}
                            {% if u.is_shortener %}<span class="badge badge-warn">Shortener</span>{% endif %}
                            {% if u.has_ip_host %}<span class="badge badge-fail">IP Host</span>{% endif %}
                            {% if u.is_suspicious_tld %}<span class="badge badge-warn">Suspicious TLD</span>{% endif %}
                        </td>
                        <td><code>{{ u.raw_url[:60] }}...</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% endif %}
    </div>
</body>
</html>
"""


def create_app(
    offline: bool = False,
    fixtures_path: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Flask:
    """Flask application factory for MailGuard."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB limit

    analyzer = MailGuardAnalyzer(
        offline=offline,
        fixtures_path=fixtures_path,
        config=config,
    )

    # In-memory storage for latest report per session
    latest_reports: Dict[str, AnalysisResult] = {}

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        )
        return response

    @app.route("/", methods=["GET"])
    def index():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        if "session_id" not in session:
            session["session_id"] = secrets.token_hex(16)

        sess_id = session.get("session_id")
        result = latest_reports.get(sess_id)
        result_dict = result.to_dict() if result else None

        return render_template_string(
            HTML_TEMPLATE,
            csrf_token=session["csrf_token"],
            result=result_dict,
            error=None,
        )

    @app.route("/upload", methods=["POST"])
    def upload():
        # Validate CSRF Token
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            return render_template_string(
                HTML_TEMPLATE,
                csrf_token=session.get("csrf_token", ""),
                result=None,
                error="Invalid or expired CSRF token. Please refresh the page.",
            ), 403

        file = request.files.get("email_file")
        if not file or not file.filename:
            return render_template_string(
                HTML_TEMPLATE,
                csrf_token=session.get("csrf_token"),
                result=None,
                error="No file uploaded. Please choose a valid .eml file.",
            ), 400

        if not file.filename.lower().endswith(".eml"):
            return render_template_string(
                HTML_TEMPLATE,
                csrf_token=session.get("csrf_token"),
                result=None,
                error="Invalid file extension. Only .eml files are accepted.",
            ), 400

        try:
            raw_bytes = file.read()
            if not raw_bytes:
                raise ValueError("Uploaded file is empty.")

            result = analyzer.analyze_bytes(raw_bytes)
            sess_id = session.get("session_id")
            if sess_id:
                latest_reports[sess_id] = result

            return render_template_string(
                HTML_TEMPLATE,
                csrf_token=session.get("csrf_token"),
                result=result.to_dict(),
                error=None,
            )
        except Exception as e:
            logger.error(f"Error processing uploaded email: {e}")
            return render_template_string(
                HTML_TEMPLATE,
                csrf_token=session.get("csrf_token"),
                result=None,
                error=f"Error analyzing email: {safe_html(str(e))}",
            ), 400

    @app.route("/download/json", methods=["GET"])
    def download_json():
        sess_id = session.get("session_id")
        result = latest_reports.get(sess_id)
        if not result:
            return abort(404, description="No analysis report found for this session.")

        json_bytes = json.dumps(result.to_dict(), indent=2).encode("utf-8")
        return Response(
            json_bytes,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=mailguard_report.json"},
        )

    return app
