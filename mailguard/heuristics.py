"""Heuristic detection engine analyzing email headers, body content, URLs, and attachments."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from rapidfuzz import fuzz

from mailguard.models import (
    AttachmentInfo,
    HeuristicFinding,
    ParsedEmail,
    Severity,
    URLInfo,
)
from mailguard.utils import (
    check_homoglyph_or_punycode,
    get_registrable_domain,
    load_config,
)

logger = logging.getLogger(__name__)


class HeuristicEngine:
    """Evaluates 17+ behavioral, structural, and content security indicators."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        self.weights = self.config.get("heuristic_weights", {})
        lists = self.config.get("lists", {})
        self.suspicious_tlds = set(lists.get("suspicious_tlds", []))
        self.trusted_brands = [b.lower() for b in lists.get("trusted_brand_domains", [])]
        self.url_shorteners = set(lists.get("url_shorteners", []))
        self.risky_extensions = set(ext.lower() for ext in lists.get("risky_attachment_extensions", []))
        self.urgency_keywords = [k.lower() for k in lists.get("urgency_keywords", [])]
        self.trusted_receivers = set(r.lower() for r in self.config.get("trusted_receivers", []))

        limits = self.config.get("limits", {})
        self.lookalike_threshold = float(limits.get("lookalike_ratio_threshold", 80.0))

    def analyze(self, email: ParsedEmail) -> List[HeuristicFinding]:
        """Run all heuristic checks on the parsed email and return findings."""
        findings: List[HeuristicFinding] = []

        # 1. Reply-To differs from From
        f = self._check_reply_to_mismatch(email)
        if f:
            findings.append(f)

        # 2. Display name contains an unrelated email address
        f = self._check_display_name_email_mismatch(email)
        if f:
            findings.append(f)

        # 3. Brand impersonation in display name or content
        f = self._check_brand_impersonation(email)
        if f:
            findings.append(f)

        # 4. Lookalike domain (typosquatting via rapidfuzz)
        f = self._check_lookalike_domain(email)
        if f:
            findings.append(f)

        # 5. Unicode / IDNA Punycode homoglyphs
        f = self._check_unicode_punycode(email)
        if f:
            findings.append(f)

        # 6. Suspicious TLD on sender domain
        f = self._check_suspicious_tld(email)
        if f:
            findings.append(f)

        # 7. Visible URL text differs from destination href
        f = self._check_url_text_href_mismatch(email)
        if f:
            findings.append(f)

        # 8. URL shorteners used
        f = self._check_url_shorteners(email)
        if f:
            findings.append(f)

        # 9. URLs containing raw IP addresses
        f = self._check_url_ip_addresses(email)
        if f:
            findings.append(f)

        # 10. Suspicious URL schemes (data:, javascript:, file:, etc.)
        f = self._check_suspicious_url_schemes(email)
        if f:
            findings.append(f)

        # 11. Double-extension attachments
        f = self._check_double_extension_attachments(email)
        if f:
            findings.append(f)

        # 12. Risky / executable attachment extensions
        f = self._check_risky_attachment_extensions(email)
        if f:
            findings.append(f)

        # 13. Urgency and credential-related keywords
        f = self._check_urgency_keywords(email)
        if f:
            findings.append(f)

        # 14. Missing or malformed Message-ID
        f = self._check_message_id_anomalies(email)
        if f:
            findings.append(f)

        # 15. Suspicious Received-chain anomalies
        f = self._check_received_chain_anomalies(email)
        if f:
            findings.append(f)

        # 16. Authentication-Results from untrusted source
        f = self._check_untrusted_auth_results(email)
        if f:
            findings.append(f)

        # 17. Sender domain combo-squatting / similarity to trusted brands
        f = self._check_sender_brand_combosquatting(email)
        if f:
            findings.append(f)

        return findings

    def _check_reply_to_mismatch(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.reply_to_domain or not email.from_domain:
            return None
        from_org = get_registrable_domain(email.from_domain)
        reply_org = get_registrable_domain(email.reply_to_domain)
        if from_org and reply_org and from_org != reply_org:
            return HeuristicFinding(
                id="HEUR-REPLYTO-MISMATCH",
                name="Reply-To Domain Mismatch",
                severity=Severity.MEDIUM,
                weight=self.weights.get("reply_to_mismatch", 15),
                description="The Reply-To address domain differs from the visible From domain, routing responses to an external destination.",
                evidence=f"From domain: {email.from_domain} vs Reply-To: {email.reply_to}",
                mitre_technique="T1672",
            )
        return None

    def _check_display_name_email_mismatch(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.from_display_name:
            return None
        # Check if an email address is embedded in the display name
        match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", email.from_display_name)
        if match:
            embedded_addr = match.group(0).lower()
            if embedded_addr != email.from_address.lower():
                return HeuristicFinding(
                    id="HEUR-DISPLAY-NAME-SPOOF",
                    name="Display Name Address Impersonation",
                    severity=Severity.HIGH,
                    weight=self.weights.get("display_name_email_mismatch", 20),
                    description="The display name contains an embedded email address that differs from the actual envelope From header.",
                    evidence=f"Display name contains '{embedded_addr}' while actual From is '{email.from_address}'",
                    mitre_technique="T1672",
                )
        return None

    def _check_brand_impersonation(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        from_org = get_registrable_domain(email.from_domain)
        haystack = f"{email.from_display_name} {email.subject}".lower()

        for brand_dom in self.trusted_brands:
            brand_name = brand_dom.split(".")[0].lower()
            # If brand name is prominent as a whole word in display name or subject
            if len(brand_name) >= 4 and re.search(r"\b" + re.escape(brand_name) + r"\b", haystack):
                # But sender domain is not owned by that brand
                if from_org != brand_dom:
                    return HeuristicFinding(
                        id="HEUR-BRAND-IMPERSONATION",
                        name="Brand Impersonation Indicator",
                        severity=Severity.HIGH,
                        weight=self.weights.get("brand_impersonation", 25),
                        description=f"Message displays brand name '{brand_name.title()}' while sender domain '{email.from_domain}' does not belong to '{brand_dom}'.",
                        evidence=f"Brand '{brand_name}' identified; actual sender is {email.from_address}",
                        mitre_technique="T1672",
                    )
        return None

    def _check_lookalike_domain(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.from_domain:
            return None
        from_dom = email.from_domain.lower()
        from_org = get_registrable_domain(from_dom)
        from_sld = from_org.split(".")[0] if from_org else from_dom.split(".")[0]

        for trusted_dom in self.trusted_brands:
            trusted_sld = trusted_dom.split(".")[0]
            # Skip if it is an exact legitimate match
            if from_org == trusted_dom or from_dom == trusted_dom or from_sld == trusted_sld:
                continue

            ratio = fuzz.ratio(from_sld, trusted_sld)
            # Edit distance & similarity ratio on SLDs
            if ratio >= self.lookalike_threshold:
                # Calculate Levenshtein distance
                lev = sum(1 for a, b in zip(from_sld, trusted_sld) if a != b) + abs(len(from_sld) - len(trusted_sld))
                if lev <= 2:
                    return HeuristicFinding(
                        id="HEUR-LOOKALIKE-DOMAIN",
                        name="Lookalike Typosquatting Domain",
                        severity=Severity.HIGH,
                        weight=self.weights.get("lookalike_domain", 30),
                        description=f"Sender domain SLD '{from_sld}' has high string similarity ({ratio:.1f}%) and small edit distance ({lev}) to trusted brand '{trusted_dom}'.",
                        evidence=f"Sender domain '{from_org}' visually mimics '{trusted_dom}'",
                        mitre_technique="T1672",
                    )
        return None

    def _check_unicode_punycode(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.from_domain:
            return None
        has_homoglyph, desc = check_homoglyph_or_punycode(email.from_domain)
        if has_homoglyph:
            return HeuristicFinding(
                id="HEUR-UNICODE-PUNYCODE",
                name="Internationalized or Homoglyph Domain",
                severity=Severity.HIGH,
                weight=self.weights.get("unicode_punycode_domain", 20),
                description=f"Sender domain utilizes Unicode homoglyphs or Punycode encoding to deceptively mimic ASCII text: {desc}.",
                evidence=f"Domain '{email.from_domain}': {desc}",
                mitre_technique="T1672",
            )
        return None

    def _check_suspicious_tld(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.from_domain:
            return None
        for tld in self.suspicious_tlds:
            if email.from_domain.endswith(tld):
                return HeuristicFinding(
                    id="HEUR-SUSPICIOUS-TLD",
                    name="Suspicious Top-Level Domain",
                    severity=Severity.MEDIUM,
                    weight=self.weights.get("suspicious_tld", 15),
                    description=f"Sender domain uses a top-level domain ({tld}) frequently associated with spam and phishing campaigns.",
                    evidence=f"Domain: {email.from_domain}",
                    mitre_technique="T1672",
                )
        return None

    def _check_url_text_href_mismatch(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        mismatched_urls = [u for u in email.urls if u.domain_mismatch]
        if mismatched_urls:
            first = mismatched_urls[0]
            return HeuristicFinding(
                id="HEUR-URL-MISMATCH",
                name="Deceptive Link Text Mismatch",
                severity=Severity.HIGH,
                weight=self.weights.get("link_text_href_mismatch", 25),
                description="Anchor text displays a legitimate brand or domain while the actual hyperlink destination directs to an unrelated domain.",
                evidence=f"Visible text: '{first.visible_text}' -> Destination: '{first.raw_url}'",
                mitre_technique="T1566.002",
            )
        return None

    def _check_url_shorteners(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        shorteners = [u for u in email.urls if u.is_shortener]
        if shorteners:
            return HeuristicFinding(
                id="HEUR-URL-SHORTENER",
                name="URL Shortener Detected",
                severity=Severity.LOW,
                weight=self.weights.get("url_shortener", 10),
                description="Email contains shortened URLs that obscure the final landing page destination.",
                evidence=f"Shortened URLs detected: {', '.join(u.raw_url for u in shorteners[:3])}",
                mitre_technique="T1566.002",
            )
        return None

    def _check_url_ip_addresses(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        ip_urls = [u for u in email.urls if u.has_ip_host]
        if ip_urls:
            return HeuristicFinding(
                id="HEUR-URL-IP-HOST",
                name="Direct IP Address in URL",
                severity=Severity.MEDIUM,
                weight=self.weights.get("url_ip_address", 20),
                description="Hyperlinks point directly to raw IP addresses instead of registered hostnames.",
                evidence=f"IP URL: {ip_urls[0].raw_url}",
                mitre_technique="T1566.002",
            )
        return None

    def _check_suspicious_url_schemes(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        bad_schemes = [u for u in email.urls if u.is_suspicious_scheme]
        if bad_schemes:
            return HeuristicFinding(
                id="HEUR-SUSPICIOUS-SCHEME",
                name="Suspicious URL Scheme",
                severity=Severity.HIGH,
                weight=self.weights.get("suspicious_url_scheme", 30),
                description=f"Message contains dangerous URL scheme handlers ({bad_schemes[0].scheme}:) designed for client-side execution.",
                evidence=f"Dangerous URL scheme: {bad_schemes[0].raw_url[:60]}",
                mitre_technique="T1566.002",
            )
        return None

    def _check_double_extension_attachments(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        double_exts = [a for a in email.attachments if a.is_double_extension]
        if double_exts:
            att = double_exts[0]
            return HeuristicFinding(
                id="HEUR-DOUBLE-EXTENSION",
                name="Double File Extension Attachment",
                severity=Severity.CRITICAL,
                weight=self.weights.get("double_extension_attachment", 35),
                description="Attachment uses multiple file extensions to mask an executable payload as an innocuous document.",
                evidence=f"Filename: '{att.filename}' (SHA256: {att.sha256[:16]}...)",
                mitre_technique="T1566.001",
            )
        return None

    def _check_risky_attachment_extensions(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        risky_atts = [a for a in email.attachments if a.is_risky]
        if risky_atts:
            att = risky_atts[0]
            return HeuristicFinding(
                id="HEUR-RISKY-ATTACHMENT",
                name="Executable or Macro Attachment",
                severity=Severity.HIGH,
                weight=self.weights.get("risky_attachment_extension", 30),
                description="Attachment contains an executable, script, or macro-enabled file extension capable of arbitrary code execution.",
                evidence=f"Filename: '{att.filename}' with extensions: {', '.join(att.detected_extensions)}",
                mitre_technique="T1566.001",
            )
        return None

    def _check_urgency_keywords(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        content_sample = f"{email.subject} {email.text_body[:1000]}".lower()
        matched_keywords = [k for k in self.urgency_keywords if k in content_sample]
        if matched_keywords:
            return HeuristicFinding(
                id="HEUR-URGENCY-LANGUAGE",
                name="Urgency and Credential Phishing Keywords",
                severity=Severity.LOW,
                weight=self.weights.get("urgency_credentials_keyword", 15),
                description="Message text exhibits psychological coercion, false urgency, or credential verification prompts.",
                evidence=f"Matched keywords: {', '.join(matched_keywords[:3])}",
                mitre_technique="T1566",
            )
        return None

    def _check_message_id_anomalies(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        for anom in email.header_anomalies:
            if anom.header_name == "Message-ID":
                return HeuristicFinding(
                    id="HEUR-ANOMALOUS-MESSAGEID",
                    name="Missing or Malformed Message-ID",
                    severity=Severity.LOW,
                    weight=self.weights.get("missing_malformed_message_id", 10),
                    description=anom.description,
                    evidence=f"Observed Message-ID: '{email.message_id}'",
                    mitre_technique="T1672",
                )
        return None

    def _check_received_chain_anomalies(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        # If Received headers exist, check for obvious forged patterns like localhost in external hops
        for hop in email.received_hops:
            if hop.from_ip and hop.from_ip.startswith("127.") and not hop.is_trusted_receiver:
                return HeuristicFinding(
                    id="HEUR-RECEIVED-ANOMALY",
                    name="Suspicious Received Hop Anomaly",
                    severity=Severity.MEDIUM,
                    weight=self.weights.get("suspicious_received_chain", 15),
                    description="Received hop indicates suspicious loopback or local origin outside trusted boundary.",
                    evidence=f"Raw hop: {hop.raw[:80]}...",
                    mitre_technique="T1672",
                )
        return None

    def _check_untrusted_auth_results(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        # If an Authentication-Results header claims PASS but comes from an untrusted receiving MTA
        for auth_h in email.auth_results_headers:
            auth_lower = auth_h.lower()
            if "pass" in auth_lower:
                is_trusted = any(tr in auth_lower for tr in self.trusted_receivers)
                if not is_trusted and self.trusted_receivers:
                    return HeuristicFinding(
                        id="HEUR-UNTRUSTED-AUTH-HEADER",
                        name="Untrusted Authentication-Results Header",
                        severity=Severity.MEDIUM,
                        weight=self.weights.get("untrusted_auth_results", 15),
                        description="Pre-existing Authentication-Results header claims authentication pass but does not originate from a configured trusted receiving gateway.",
                        evidence=f"Header: {auth_h[:80]}...",
                        mitre_technique="T1672",
                    )
        return None

    def _check_sender_brand_combosquatting(self, email: ParsedEmail) -> Optional[HeuristicFinding]:
        if not email.from_domain:
            return None
        from_dom = email.from_domain.lower()
        from_org = get_registrable_domain(from_dom)

        for trusted_dom in self.trusted_brands:
            brand_token = trusted_dom.split(".")[0]
            # If the brand token is inside the domain (e.g. paypal-security.com or verify-apple.com)
            if len(brand_token) >= 4 and brand_token in from_dom:
                if from_org != trusted_dom:
                    return HeuristicFinding(
                        id="HEUR-BRAND-COMBOSQUATTING",
                        name="Combo-Squatting Brand Similarity",
                        severity=Severity.HIGH,
                        weight=self.weights.get("sender_brand_similarity", 25),
                        description=f"Sender domain incorporates brand name '{brand_token}' alongside deceptive prefixes/suffixes while not registered to '{trusted_dom}'.",
                        evidence=f"Sender domain: '{email.from_domain}' embeds brand '{brand_token}'",
                        mitre_technique="T1672",
                    )
        return None
