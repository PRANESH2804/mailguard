"""SOAR Ticketing Export module generating structured incident payloads for automated playbook ingestion."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from mailguard.models import (
    AnalysisResult,
    RecommendedAction,
    Verdict,
)

logger = logging.getLogger(__name__)


def derive_soar_severity(result: AnalysisResult) -> str:
    """Derive standard SOAR ticket severity based on verdict and risk factors."""
    has_risky_att = any(a.is_risky or a.is_double_extension for a in result.attachments)
    
    if result.verdict == Verdict.SPOOFED:
        if result.risk_score >= 85 or has_risky_att:
            return "CRITICAL"
        return "HIGH"
    elif result.verdict == Verdict.SUSPICIOUS:
        if has_risky_att or result.risk_score >= 50:
            return "HIGH"
        return "MEDIUM"
    return "LOW"


def generate_analyst_summary(result: AnalysisResult) -> str:
    """Generate concise, actionable 1-2 sentence executive analyst summary."""
    action_val = (
        result.recommended_action.value
        if isinstance(result.recommended_action, RecommendedAction)
        else str(result.recommended_action)
    )
    verdict_val = (
        result.verdict.value
        if isinstance(result.verdict, Verdict)
        else str(result.verdict)
    )

    reasons_str = "; ".join(result.top_reasons[:2]) if result.top_reasons else "No major risks identified."
    summary = (
        f"MailGuard assessed message '{result.subject}' from '{result.from_address}' as {verdict_val} "
        f"(Risk Score: {result.risk_score}/100, Action: {action_val}). "
        f"Primary factors: {reasons_str}. Advisory only; SOC review recommended."
    )
    return summary


def export_soar_ticket(result: AnalysisResult) -> Dict[str, Any]:
    """Generate a single standardized SOAR ticketing incident payload.

    Schema:
        id: Unique incident/ticket ID.
        severity: SOAR severity (LOW | MEDIUM | HIGH | CRITICAL).
        verdict: Defensive risk verdict (LEGITIMATE | SUSPICIOUS | SPOOFED).
        recommended_action: Advisory recommendation (ALLOW | QUARANTINE_AND_REVIEW | ESCALATE_TO_SOC).
        risk_score: Numerical risk score (0-100).
        indicators: Observable IOCs (sender domains, IPs, URLs, attachment hashes).
        reasons: Ranked contributing risk factors.
        mitre_techniques: Correlated ATT&CK techniques with tactics.
        short_analyst_summary: Concise triage briefing.
    """
    # Deterministic incident ID
    if result.message_id and result.message_id.strip():
        ticket_id = f"MG-{hashlib.sha256(result.message_id.encode('utf-8')).hexdigest()[:12].upper()}"
    else:
        seed = f"{result.timestamp}_{result.from_address}_{result.subject}"
        ticket_id = f"MG-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

    # Extract distinct sender domains
    sender_domains: List[str] = []
    if result.from_domain and result.from_domain not in sender_domains:
        sender_domains.append(result.from_domain)
    if result.return_path_domain and result.return_path_domain not in sender_domains:
        sender_domains.append(result.return_path_domain)

    # Extract distinct IPs
    originating_ips: List[str] = []
    if result.originating_ip:
        originating_ips.append(result.originating_ip)

    # Extract unique URLs
    urls: List[str] = list({u.raw_url for u in result.urls if u.raw_url})

    # Extract attachment SHA-256 hashes
    attachment_hashes: List[str] = list({a.sha256 for a in result.attachments if a.sha256})

    # MITRE ATT&CK technique summary
    mitre_techniques = [
        {
            "id": m.technique_id,
            "name": m.technique_name,
            "tactic": m.tactic,
            "rationale": m.rationale,
        }
        for m in result.mitre_techniques
    ]

    action_val = (
        result.recommended_action.value
        if isinstance(result.recommended_action, RecommendedAction)
        else str(result.recommended_action)
    )
    verdict_val = (
        result.verdict.value
        if isinstance(result.verdict, Verdict)
        else str(result.verdict)
    )

    ticket: Dict[str, Any] = {
        "id": ticket_id,
        "severity": derive_soar_severity(result),
        "verdict": verdict_val,
        "recommended_action": action_val,
        "risk_score": result.risk_score,
        "indicators": {
            "sender_domains": sender_domains,
            "originating_ips": originating_ips,
            "urls": urls,
            "attachment_hashes": attachment_hashes,
        },
        "reasons": result.top_reasons,
        "mitre_techniques": mitre_techniques,
        "short_analyst_summary": generate_analyst_summary(result),
    }

    return ticket


def save_soar_ticket(result: AnalysisResult, output_path: str | Path) -> Path:
    """Export SOAR ticket to disk as formatted JSON."""
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    ticket_data = export_soar_ticket(result)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(ticket_data, f, indent=2)
    logger.info(f"Exported SOAR ticket to {out_file}")
    return out_file
