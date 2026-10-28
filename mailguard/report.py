"""Report generation module producing Rich terminal displays, JSON exports, and defensive HTML reports."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mailguard.models import (
    AnalysisResult,
    AuthStatus,
    Verdict,
)
from mailguard.utils import safe_html

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates formatted reports in Terminal (Rich), JSON, and HTML formats."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def generate_json(self, result: AnalysisResult, indent: int = 2) -> str:
        """Serialize analysis result to structured JSON string."""
        return json.dumps(result.to_dict(), indent=indent)

    def render_terminal(self, result: AnalysisResult) -> None:
        """Display an interactive, SOC-ready terminal report using Rich."""
        # 1. Verdict Color Styling
        verdict_color = "green"
        if result.verdict == Verdict.SUSPICIOUS:
            verdict_color = "yellow"
        elif result.verdict == Verdict.SPOOFED:
            verdict_color = "bold red"

        # 2. Main Title Banner
        title_text = Text()
        title_text.append("MAILGUARD EMAIL AUTHENTICATION & SPOOFING REPORT\n", style="bold cyan")
        title_text.append(f"Verdict: {result.verdict.value}  |  Risk Score: {result.risk_score}/100\n", style=verdict_color)
        title_text.append(f"Subject: {result.subject}\n", style="white")
        title_text.append(f"From: {result.from_address} | MsgID: {result.message_id or 'N/A'}", style="dim")

        self.console.print(Panel(title_text, expand=False, border_style=verdict_color))

        # 3. Authentication & Alignment Summary Table
        auth_table = Table(title="Authentication & Identifier Alignment", expand=True)
        auth_table.add_column("Protocol / Layer", style="cyan", no_wrap=True)
        auth_table.add_column("Status", style="bold")
        auth_table.add_column("Domain / Identifier", style="magenta")
        auth_table.add_column("Technical Details & RFC Explanation")

        # SPF row
        spf_style = "green" if result.spf.status == AuthStatus.PASS else ("yellow" if result.spf.status in (AuthStatus.SOFTFAIL, AuthStatus.NEUTRAL) else "red")
        auth_table.add_row(
            "SPF (RFC 7208)",
            Text(result.spf.status.value, style=spf_style),
            result.spf.domain or "N/A",
            result.spf.explanation,
        )

        # DKIM row
        dkim_style = "green" if result.dkim.overall_status == AuthStatus.PASS else "red"
        dkim_domains = ", ".join(s.signing_domain for s in result.dkim.signatures) or "None"
        auth_table.add_row(
            "DKIM (RFC 6376)",
            Text(result.dkim.overall_status.value, style=dkim_style),
            f"d={dkim_domains}",
            result.dkim.explanation,
        )

        # Alignment row
        align_spf = "Relaxed" if result.alignment.spf_aligned_relaxed else ("Strict" if result.alignment.spf_aligned_strict else "FAIL")
        align_dkim = "Relaxed" if result.alignment.dkim_aligned_relaxed else ("Strict" if result.alignment.dkim_aligned_strict else "FAIL")
        align_style = "green" if (result.alignment.spf_aligned_relaxed or result.alignment.dkim_aligned_relaxed) else "red"
        auth_table.add_row(
            "Alignment",
            Text(f"SPF:{align_spf} | DKIM:{align_dkim}", style=align_style),
            result.from_domain,
            result.alignment.details,
        )

        # DMARC row
        dmarc_style = "green" if result.dmarc.status == AuthStatus.PASS else "red"
        auth_table.add_row(
            "DMARC (RFC 7489)",
            Text(result.dmarc.status.value, style=dmarc_style),
            f"p={result.dmarc.policy}",
            result.dmarc.explanation,
        )

        self.console.print(auth_table)

        # 4. Top Contributing Risk Reasons
        if result.top_reasons:
            reasons_table = Table(title="Top Risk Score Contributors", expand=True)
            reasons_table.add_column("#", style="dim", width=4)
            reasons_table.add_column("Factor & Points Contribution", style="bold yellow")
            for idx, r in enumerate(result.top_reasons, 1):
                reasons_table.add_row(str(idx), r)
            self.console.print(reasons_table)

        # 5. Heuristic Indicators
        if result.heuristics:
            heur_table = Table(title="Observed Heuristic Risk Indicators", expand=True)
            heur_table.add_column("Rule ID", style="cyan", width=22)
            heur_table.add_column("Severity", style="bold", width=10)
            heur_table.add_column("Weight", justify="right", width=8)
            heur_table.add_column("Description & Technical Evidence")

            for h in result.heuristics:
                sev_style = "red" if h.severity.value in ("CRITICAL", "HIGH") else ("yellow" if h.severity.value == "MEDIUM" else "blue")
                heur_table.add_row(
                    h.id,
                    Text(h.severity.value, style=sev_style),
                    str(h.weight),
                    f"{h.name}\n[dim]{h.evidence}[/dim]",
                )
            self.console.print(heur_table)

        # 6. MITRE ATT&CK Mappings
        if result.mitre_techniques:
            mitre_table = Table(title="MITRE ATT&CK Contextual Technique Mappings", expand=True)
            mitre_table.add_column("Technique ID", style="bold red", width=14)
            mitre_table.add_column("Technique Name", style="bold")
            mitre_table.add_column("Tactic", style="magenta")
            mitre_table.add_column("Adversary Rationale & Mapped Findings")

            for m in result.mitre_techniques:
                mitre_table.add_row(
                    m.technique_id,
                    m.technique_name,
                    m.tactic,
                    f"{m.rationale}\n[dim]Findings: {', '.join(m.finding_ids)}[/dim]",
                )
            self.console.print(mitre_table)

        # 7. Attachments & URLs (if present)
        if result.attachments:
            att_table = Table(title="Extracted Attachments", expand=True)
            att_table.add_column("Filename", style="bold")
            att_table.add_column("Type", style="dim")
            att_table.add_column("Size (Bytes)", justify="right")
            att_table.add_column("SHA-256 Hash", style="cyan")
            att_table.add_column("Risk Flag", style="bold red")

            for a in result.attachments:
                risk_label = "HIGH RISK" if (a.is_risky or a.is_double_extension) else "Benign"
                risk_color = "red" if risk_label == "HIGH RISK" else "green"
                att_table.add_row(
                    a.filename,
                    a.content_type,
                    str(a.size_bytes),
                    a.sha256[:20] + "...",
                    Text(risk_label, style=risk_color),
                )
            self.console.print(att_table)

    def render_directory_table(self, results: List[AnalysisResult]) -> None:
        """Render a concise batch summary table for multiple analyzed emails."""
        table = Table(title="MailGuard Batch Email Analysis Summary", expand=True)
        table.add_column("Message-ID / File", style="dim", no_wrap=True)
        table.add_column("From Address", style="cyan")
        table.add_column("SPF", justify="center")
        table.add_column("DKIM", justify="center")
        table.add_column("DMARC", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Verdict", style="bold")

        for r in results:
            v_color = "green" if r.verdict == Verdict.LEGITIMATE else ("yellow" if r.verdict == Verdict.SUSPICIOUS else "red")
            spf_color = "green" if r.spf.status == AuthStatus.PASS else "red"
            dkim_color = "green" if r.dkim.overall_status == AuthStatus.PASS else "red"
            dmarc_color = "green" if r.dmarc.status == AuthStatus.PASS else "red"

            table.add_row(
                (r.message_id or "N/A")[:25],
                r.from_address[:30],
                Text(r.spf.status.value, style=spf_color),
                Text(r.dkim.overall_status.value, style=dkim_color),
                Text(r.dmarc.status.value, style=dmarc_color),
                str(r.risk_score),
                Text(r.verdict.value, style=v_color),
            )

        self.console.print(table)

    def generate_html(self, result: AnalysisResult, output_path: Optional[str] = None) -> str:
        """Generate a standalone, interactive HTML security report."""
        v_class = result.verdict.value.lower()
        score_pct = result.risk_score

        heur_rows = ""
        for h in result.heuristics:
            heur_rows += f"""
            <tr>
                <td><code>{safe_html(h.id)}</code></td>
                <td><span class="badge {h.severity.value.lower()}">{safe_html(h.severity.value)}</span></td>
                <td>{h.weight}</td>
                <td><strong>{safe_html(h.name)}</strong><br><small>{safe_html(h.evidence)}</small></td>
            </tr>
            """

        reasons_items = "".join(f"<li>{safe_html(r)}</li>" for r in result.top_reasons)
        
        mitre_rows = ""
        for m in result.mitre_techniques:
            mitre_rows += f"""
            <tr>
                <td><code>{safe_html(m.technique_id)}</code></td>
                <td><strong>{safe_html(m.technique_name)}</strong></td>
                <td>{safe_html(m.tactic)}</td>
                <td>{safe_html(m.rationale)}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailGuard Report - {safe_html(result.subject)}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --panel-bg: #1e293b;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --border: #334155;
            --legit: #10b981;
            --suspicious: #f59e0b;
            --spoofed: #ef4444;
            --accent: #38bdf8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header-card {{
            background: var(--panel-bg);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .verdict-badge {{
            font-size: 1.5rem;
            font-weight: bold;
            padding: 10px 24px;
            border-radius: 8px;
            text-transform: uppercase;
        }}
        .verdict-legitimate {{ background: rgba(16, 185, 129, 0.2); color: var(--legit); border: 1px solid var(--legit); }}
        .verdict-suspicious {{ background: rgba(245, 158, 11, 0.2); color: var(--suspicious); border: 1px solid var(--suspicious); }}
        .verdict-spoofed {{ background: rgba(239, 68, 68, 0.2); color: var(--spoofed); border: 1px solid var(--spoofed); }}

        .score-bar-bg {{
            background: #334155;
            height: 12px;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 8px;
        }}
        .score-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--legit) 0%, var(--suspicious) 50%, var(--spoofed) 100%);
            width: {score_pct}%;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--panel-bg);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; }}
        code {{ background: #090d16; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: var(--accent); }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .badge.pass, .badge.low {{ background: rgba(16, 185, 129, 0.2); color: var(--legit); }}
        .badge.fail, .badge.high, .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--spoofed); }}
        .badge.medium {{ background: rgba(245, 158, 11, 0.2); color: var(--suspicious); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-card">
            <div>
                <h1 style="margin: 0 0 8px 0; font-size: 1.6rem;">MailGuard Email Security Analysis</h1>
                <p style="margin: 0; color: var(--text-dim);">Subject: <strong>{safe_html(result.subject)}</strong></p>
                <p style="margin: 4px 0 0 0; color: var(--text-dim); font-size: 0.9rem;">From: <code>{safe_html(result.from_address)}</code> | Message-ID: <code>{safe_html(result.message_id or 'N/A')}</code></p>
            </div>
            <div style="text-align: right;">
                <div class="verdict-badge verdict-{v_class}">{safe_html(result.verdict.value)}</div>
                <div style="margin-top: 8px; font-size: 0.9rem;">Risk Score: <strong>{result.risk_score}</strong> / 100</div>
                <div class="score-bar-bg" style="width: 160px; display: inline-block;">
                    <div class="score-bar-fill"></div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h3 style="margin-top: 0;">Authentication Framework</h3>
                <table>
                    <thead>
                        <tr><th>Protocol</th><th>Status</th><th>Evaluated Identity</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>SPF</td><td><span class="badge {result.spf.status.value.lower()}">{safe_html(result.spf.status.value)}</span></td><td>{safe_html(result.spf.domain)}</td></tr>
                        <tr><td>DKIM</td><td><span class="badge {result.dkim.overall_status.value.lower()}">{safe_html(result.dkim.overall_status.value)}</span></td><td>{safe_html(", ".join(s.signing_domain for s in result.dkim.signatures) or 'None')}</td></tr>
                        <tr><td>DMARC</td><td><span class="badge {result.dmarc.status.value.lower()}">{safe_html(result.dmarc.status.value)}</span></td><td>policy={safe_html(result.dmarc.policy)} (pct={result.dmarc.pct}%)</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h3 style="margin-top: 0;">Top Risk Contributors</h3>
                <ul style="padding-left: 20px; color: var(--text-main); margin-bottom: 0;">
                    {reasons_items}
                </ul>
            </div>
        </div>

        <div class="card" style="margin-bottom: 24px;">
            <h3 style="margin-top: 0;">Heuristic Findings ({len(result.heuristics)})</h3>
            <table>
                <thead>
                    <tr><th>Rule ID</th><th>Severity</th><th>Weight</th><th>Description & Evidence</th></tr>
                </thead>
                <tbody>
                    {heur_rows if heur_rows else '<tr><td colspan="4" style="text-align:center; color: var(--text-dim);">No suspicious heuristics triggered.</td></tr>'}
                </tbody>
            </table>
        </div>

        {f'''
        <div class="card">
            <h3 style="margin-top: 0;">MITRE ATT&CK Mappings</h3>
            <table>
                <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Rationale</th></tr></thead>
                <tbody>{mitre_rows}</tbody>
            </table>
        </div>
        ''' if mitre_rows else ''}
    </div>
</body>
</html>
"""
        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report successfully written to {out_file}")

        return html_content
