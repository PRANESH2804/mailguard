"""Data models representing parsed emails, authentication results, heuristics, and reports."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional


class Verdict(str, Enum):
    """Defensive risk classification for an analyzed email."""
    LEGITIMATE = "LEGITIMATE"
    SUSPICIOUS = "SUSPICIOUS"
    SPOOFED = "SPOOFED"


class AuthStatus(str, Enum):
    """Standardized authentication check status."""
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    PERMERROR = "PERMERROR"
    TEMPERROR = "TEMPERROR"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    """Severity levels for heuristic findings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class HeaderAnomaly:
    """Represents a malformed or suspicious header anomaly."""
    header_name: str
    description: str
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        return {
            "header_name": self.header_name,
            "description": self.description,
            "severity": self.severity.value,
        }


@dataclass
class AttachmentInfo:
    """Metadata and security indicators for an email attachment."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_risky: bool = False
    is_double_extension: bool = False
    detected_extensions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "is_risky": self.is_risky,
            "is_double_extension": self.is_double_extension,
            "detected_extensions": self.detected_extensions,
        }


@dataclass
class URLInfo:
    """Parsed URL indicator with security heuristic flags."""
    raw_url: str
    scheme: str
    domain: str
    visible_text: Optional[str] = None
    is_shortener: bool = False
    has_ip_host: bool = False
    domain_mismatch: bool = False
    is_suspicious_tld: bool = False
    is_suspicious_scheme: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_url": self.raw_url,
            "scheme": self.scheme,
            "domain": self.domain,
            "visible_text": self.visible_text,
            "is_shortener": self.is_shortener,
            "has_ip_host": self.has_ip_host,
            "domain_mismatch": self.domain_mismatch,
            "is_suspicious_tld": self.is_suspicious_tld,
            "is_suspicious_scheme": self.is_suspicious_scheme,
        }


@dataclass
class ReceivedHop:
    """Represents a single parsed Received header hop."""
    raw: str
    by: Optional[str] = None
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    date: Optional[str] = None
    is_trusted_receiver: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "by": self.by,
            "from_host": self.from_host,
            "from_ip": self.from_ip,
            "date": self.date,
            "is_trusted_receiver": self.is_trusted_receiver,
        }


@dataclass
class ParsedEmail:
    """Structured representation of a parsed raw .eml message."""
    message_id: str
    date: Optional[str]
    subject: str
    from_display_name: str
    from_address: str
    from_domain: str
    to_addresses: List[str]
    cc_addresses: List[str]
    return_path: Optional[str]
    return_path_domain: Optional[str]
    reply_to: Optional[str]
    reply_to_domain: Optional[str]
    received_hops: List[ReceivedHop]
    candidate_originating_ip: Optional[str]
    auth_results_headers: List[str]
    dkim_signatures_raw: List[str]
    content_types: List[str]
    text_body: str
    html_body: str
    urls: List[URLInfo]
    attachments: List[AttachmentInfo]
    header_anomalies: List[HeaderAnomaly]
    raw_bytes: bytes
    size_bytes: int


@dataclass
class SPFResult:
    """Outcome of SPF verification."""
    status: AuthStatus
    identity: str
    domain: str
    mechanism: Optional[str] = None
    explanation: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "identity": self.identity,
            "domain": self.domain,
            "mechanism": self.mechanism,
            "explanation": self.explanation,
            "error": self.error,
        }


@dataclass
class DKIMSignatureResult:
    """Outcome of single DKIM-Signature verification."""
    signing_domain: str
    selector: str
    algorithm: str
    body_hash_status: str
    verification_status: AuthStatus
    explanation: str
    error: Optional[str] = None
    expires_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signing_domain": self.signing_domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "body_hash_status": self.body_hash_status,
            "verification_status": self.verification_status.value,
            "explanation": self.explanation,
            "error": self.error,
            "expires_at": self.expires_at,
        }


@dataclass
class DKIMResult:
    """Aggregated DKIM evaluation result."""
    signatures: List[DKIMSignatureResult] = field(default_factory=list)
    overall_status: AuthStatus = AuthStatus.NONE
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status.value,
            "explanation": self.explanation,
            "signatures": [sig.to_dict() for sig in self.signatures],
        }


@dataclass
class AlignmentResult:
    """Evaluation of SPF and DKIM domain alignment with the RFC5322.From domain."""
    visible_from_domain: str
    spf_domain: Optional[str]
    dkim_domains: List[str]
    spf_aligned_strict: bool = False
    spf_aligned_relaxed: bool = False
    dkim_aligned_strict: bool = False
    dkim_aligned_relaxed: bool = False
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "visible_from_domain": self.visible_from_domain,
            "spf_domain": self.spf_domain,
            "dkim_domains": self.dkim_domains,
            "spf_aligned_strict": self.spf_aligned_strict,
            "spf_aligned_relaxed": self.spf_aligned_relaxed,
            "dkim_aligned_strict": self.dkim_aligned_strict,
            "dkim_aligned_relaxed": self.dkim_aligned_relaxed,
            "details": self.details,
        }


@dataclass
class DMARCResult:
    """Evaluation of DMARC policy compliance."""
    status: AuthStatus
    domain: str
    org_domain: Optional[str]
    policy: str
    subdomain_policy: Optional[str]
    pct: int = 100
    spf_aligned_pass: bool = False
    dkim_aligned_pass: bool = False
    record_raw: Optional[str] = None
    explanation: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "domain": self.domain,
            "org_domain": self.org_domain,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "pct": self.pct,
            "spf_aligned_pass": self.spf_aligned_pass,
            "dkim_aligned_pass": self.dkim_aligned_pass,
            "record_raw": self.record_raw,
            "explanation": self.explanation,
            "error": self.error,
        }


@dataclass
class HeuristicFinding:
    """Specific behavioral or format risk indicator detected in the email."""
    id: str
    name: str
    severity: Severity
    weight: int
    description: str
    evidence: str
    confidence: str = "HIGH"
    mitre_technique: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "weight": self.weight,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class MITREMapping:
    """Mapping of observed evidence to MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: str
    rationale: str
    finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "rationale": self.rationale,
            "finding_ids": self.finding_ids,
        }


@dataclass
class EnrichmentResult:
    """Optional external threat intelligence lookup result."""
    indicator: str
    indicator_type: str
    provider: str
    verdict: str
    score: Optional[int] = None
    malicious_votes: Optional[int] = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "provider": self.provider,
            "verdict": self.verdict,
            "score": self.score,
            "malicious_votes": self.malicious_votes,
            "details": self.details,
        }


@dataclass
class AnalysisResult:
    """Comprehensive analysis report for an email message."""
    timestamp: str
    message_id: str
    subject: str
    from_address: str
    from_domain: str
    return_path: Optional[str]
    return_path_domain: Optional[str]
    originating_ip: Optional[str]
    recipients: List[str]
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    alignment: AlignmentResult
    heuristics: List[HeuristicFinding]
    risk_score: int
    verdict: Verdict
    top_reasons: List[str]
    mitre_techniques: List[MITREMapping]
    urls: List[URLInfo]
    attachments: List[AttachmentInfo]
    enrichment_results: List[EnrichmentResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "subject": self.subject,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "return_path": self.return_path,
            "return_path_domain": self.return_path_domain,
            "originating_ip": self.originating_ip,
            "recipients": self.recipients,
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "alignment": self.alignment.to_dict(),
            "heuristics": [h.to_dict() for h in self.heuristics],
            "risk_score": self.risk_score,
            "verdict": self.verdict.value,
            "top_reasons": self.top_reasons,
            "mitre_techniques": [m.to_dict() for m in self.mitre_techniques],
            "urls": [u.to_dict() for u in self.urls],
            "attachments": [a.to_dict() for a in self.attachments],
            "enrichment_results": [e.to_dict() for e in self.enrichment_results],
        }
