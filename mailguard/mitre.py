"""MITRE ATT&CK mapping module correlating email authentication and heuristic findings to adversary techniques."""

from __future__ import annotations

import logging
from typing import Dict, List

from mailguard.models import (
    AlignmentResult,
    AuthStatus,
    DKIMResult,
    DMARCResult,
    HeuristicFinding,
    MITREMapping,
    SPFResult,
)

logger = logging.getLogger(__name__)

# Canonical MITRE ATT&CK definitions
TECHNIQUES_DEF = {
    "T1672": {
        "name": "Subvert Trust Controls: Email Spoofing",
        "tactic": "Defense Evasion",
        "description": "Adversaries may spoof email headers (such as From or Return-Path) to disguise the origin of malicious communications.",
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with malicious attachments to execute code on victim systems.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with malicious links to direct victims to credential harvesting or malware sites.",
    },
    "T1566.003": {
        "name": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage legitimate third-party cloud services to deliver phishing lures or bypass perimeter filters.",
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactic": "Lateral Movement",
        "description": "Adversaries may send spearphishing messages to internal employees from compromised internal accounts or domains.",
    },
}


class MITREMapper:
    """Correlates observed defensive evidence with relevant MITRE ATT&CK enterprise techniques."""

    def map_evidence(
        self,
        spf: SPFResult,
        dkim: DKIMResult,
        dmarc: DMARCResult,
        alignment: AlignmentResult,
        heuristics: List[HeuristicFinding],
    ) -> List[MITREMapping]:
        """Produce evidence-based MITRE ATT&CK mappings."""
        mappings: Dict[str, MITREMapping] = {}

        # 1. T1672 - Email Spoofing
        spoof_finding_ids = []
        if spf.status in (AuthStatus.FAIL, AuthStatus.SOFTFAIL):
            spoof_finding_ids.append("AUTH-SPF-FAIL")
        if dkim.overall_status == AuthStatus.FAIL:
            spoof_finding_ids.append("AUTH-DKIM-FAIL")
        if dmarc.status == AuthStatus.FAIL:
            spoof_finding_ids.append("AUTH-DMARC-FAIL")
        if not alignment.spf_aligned_relaxed and alignment.spf_domain:
            spoof_finding_ids.append("ALIGN-SPF-FAIL")

        for h in heuristics:
            if h.mitre_technique == "T1672" or "spoof" in h.id.lower() or "lookalike" in h.id.lower():
                spoof_finding_ids.append(h.id)

        if spoof_finding_ids:
            t_def = TECHNIQUES_DEF["T1672"]
            mappings["T1672"] = MITREMapping(
                technique_id="T1672",
                technique_name=t_def["name"],
                tactic=t_def["tactic"],
                rationale="Sender identity failed cryptographic or policy validation (SPF/DKIM/DMARC) or exhibited visual spoofing indicators.",
                finding_ids=spoof_finding_ids,
            )

        # 2. T1566.001 - Spearphishing Attachment
        att_finding_ids = [h.id for h in heuristics if h.mitre_technique == "T1566.001" or "attachment" in h.id.lower()]
        if att_finding_ids:
            t_def = TECHNIQUES_DEF["T1566.001"]
            mappings["T1566.001"] = MITREMapping(
                technique_id="T1566.001",
                technique_name=t_def["name"],
                tactic=t_def["tactic"],
                rationale="Message carries suspicious, macro-enabled, or double-extension attachment payloads.",
                finding_ids=att_finding_ids,
            )

        # 3. T1566.002 - Spearphishing Link
        link_finding_ids = [h.id for h in heuristics if h.mitre_technique == "T1566.002" or "url" in h.id.lower()]
        if link_finding_ids:
            t_def = TECHNIQUES_DEF["T1566.002"]
            mappings["T1566.002"] = MITREMapping(
                technique_id="T1566.002",
                technique_name=t_def["name"],
                tactic=t_def["tactic"],
                rationale="Message embeds deceptive anchor links, URL shorteners, raw IP destinations, or execution schemes.",
                finding_ids=link_finding_ids,
            )

        # 4. T1566.003 - Spearphishing via Service (contextual evidence only)
        service_finding_ids = [h.id for h in heuristics if h.mitre_technique == "T1566.003" or "service" in h.id.lower()]
        if service_finding_ids:
            t_def = TECHNIQUES_DEF["T1566.003"]
            mappings["T1566.003"] = MITREMapping(
                technique_id="T1566.003",
                technique_name=t_def["name"],
                tactic=t_def["tactic"],
                rationale="Message leverages third-party cloud service lures or platforms to deliver malicious content.",
                finding_ids=service_finding_ids,
            )

        # 5. T1534 - Internal Spearphishing (contextual evidence only)
        internal_finding_ids = [h.id for h in heuristics if h.mitre_technique == "T1534" or "internal" in h.id.lower()]
        if internal_finding_ids:
            t_def = TECHNIQUES_DEF["T1534"]
            mappings["T1534"] = MITREMapping(
                technique_id="T1534",
                technique_name=t_def["name"],
                tactic=t_def["tactic"],
                rationale="Observed indicators indicate lateral movement or internal email identity abuse.",
                finding_ids=internal_finding_ids,
            )

        return list(mappings.values())
