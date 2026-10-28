"""MIME email parser with defensive security controls, URL analysis, and header anomaly detection."""

from __future__ import annotations

import email
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parseaddr
import hashlib
import ipaddress
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from mailguard.models import (
    AttachmentInfo,
    HeaderAnomaly,
    ParsedEmail,
    ReceivedHop,
    Severity,
    URLInfo,
)
from mailguard.utils import (
    get_registrable_domain,
    is_ip_address,
    is_private_or_reserved_ip,
    load_config,
    sanitize_header,
)

logger = logging.getLogger(__name__)

# Common regex patterns
IP_REGEX = re.compile(r"\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b)\]?")
URL_REGEX = re.compile(r"(?i)\b(?:https?|ftp)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]")


class EmailParser:
    """Defensive MIME email parser enforcing resource bounds and security sanity checks."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        limits = self.config.get("limits", {})
        self.max_message_bytes = int(limits.get("max_message_bytes", 26214400))
        self.max_attachment_bytes = int(limits.get("max_attachment_bytes", 10485760))
        self.max_urls = int(limits.get("max_urls_to_analyze", 100))

        lists = self.config.get("lists", {})
        self.suspicious_tlds = set(lists.get("suspicious_tlds", []))
        self.url_shorteners = set(lists.get("url_shorteners", []))
        self.risky_extensions = set(ext.lower() for ext in lists.get("risky_attachment_extensions", []))
        self.trusted_receivers = set(r.lower() for r in self.config.get("trusted_receivers", []))

    def parse_file(self, file_path: str | Path) -> ParsedEmail:
        """Parse raw .eml file from disk with size and safety checks."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Email file not found: {file_path}")

        file_size = path.stat().st_size
        if file_size > self.max_message_bytes:
            raise ValueError(
                f"Email file exceeds maximum size limit ({file_size} > {self.max_message_bytes} bytes)"
            )

        with open(path, "rb") as f:
            raw_bytes = f.read()

        return self.parse_bytes(raw_bytes)

    def parse_bytes(self, raw_bytes: bytes) -> ParsedEmail:
        """Parse email message directly from raw bytes."""
        size_bytes = len(raw_bytes)
        if size_bytes > self.max_message_bytes:
            raise ValueError(
                f"Email content exceeds maximum allowed size ({size_bytes} > {self.max_message_bytes} bytes)"
            )

        # Parse message using modern python email policy
        try:
            msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception as e:
            logger.warning(f"Error parsing with default policy ({e}); falling back to compat32")
            msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

        header_anomalies: List[HeaderAnomaly] = []

        # Extract & sanitize core headers
        message_id, m_anom = self._extract_message_id(msg)
        if m_anom:
            header_anomalies.extend(m_anom)

        date_str = sanitize_header(msg.get("Date"))
        subject = self._decode_header_value(msg.get("Subject", ""))

        # From address & display name
        from_display, from_addr, from_domain, from_anoms = self._extract_from(msg)
        header_anomalies.extend(from_anoms)

        # Recipients
        to_addrs = self._extract_addresses(msg.get_all("To", []))
        cc_addrs = self._extract_addresses(msg.get_all("Cc", []))

        # Return-Path & Reply-To
        return_path, return_path_domain = self._extract_single_addr(msg.get("Return-Path"))
        reply_to, reply_to_domain = self._extract_single_addr(msg.get("Reply-To"))

        # Received headers & originating IP detection
        received_hops, originating_ip = self._process_received_headers(msg)

        # Authentication-Results & DKIM-Signature headers
        auth_results = [sanitize_header(h) for h in msg.get_all("Authentication-Results", [])]
        dkim_sigs = [sanitize_header(h) for h in msg.get_all("DKIM-Signature", [])]

        # Bodies & MIME types
        content_types: List[str] = []
        text_body, html_body, attachments = self._extract_payloads(msg)

        # Content types collection
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype and ctype not in content_types:
                    content_types.append(ctype)
        else:
            content_types.append(msg.get_content_type() or "text/plain")

        # URLs extraction & heuristics
        urls = self._extract_urls(text_body, html_body)

        return ParsedEmail(
            message_id=message_id,
            date=date_str,
            subject=subject,
            from_display_name=from_display,
            from_address=from_addr,
            from_domain=from_domain,
            to_addresses=to_addrs,
            cc_addresses=cc_addrs,
            return_path=return_path,
            return_path_domain=return_path_domain,
            reply_to=reply_to,
            reply_to_domain=reply_to_domain,
            received_hops=received_hops,
            candidate_originating_ip=originating_ip,
            auth_results_headers=auth_results,
            dkim_signatures_raw=dkim_sigs,
            content_types=content_types,
            text_body=text_body,
            html_body=html_body,
            urls=urls,
            attachments=attachments,
            header_anomalies=header_anomalies,
            raw_bytes=raw_bytes,
            size_bytes=size_bytes,
        )

    def _decode_header_value(self, raw_val: Any) -> str:
        """Safely decode MIME encoded header words (e.g. =?UTF-8?B?...?=)."""
        if not raw_val:
            return ""
        try:
            decoded = str(make_header(decode_header(str(raw_val))))
            return sanitize_header(decoded)
        except Exception:
            return sanitize_header(str(raw_val))

    def _extract_message_id(self, msg: EmailMessage) -> Tuple[str, List[HeaderAnomaly]]:
        anomalies: List[HeaderAnomaly] = []
        raw_ids = msg.get_all("Message-ID", [])
        if not raw_ids:
            anomalies.append(
                HeaderAnomaly(
                    header_name="Message-ID",
                    description="Missing RFC 5322 Message-ID header",
                    severity=Severity.LOW,
                )
            )
            return "", anomalies

        if len(raw_ids) > 1:
            anomalies.append(
                HeaderAnomaly(
                    header_name="Message-ID",
                    description=f"Multiple Message-ID headers present ({len(raw_ids)})",
                    severity=Severity.MEDIUM,
                )
            )

        msg_id = sanitize_header(raw_ids[0])
        if not (msg_id.startswith("<") and msg_id.endswith(">") and "@" in msg_id):
            anomalies.append(
                HeaderAnomaly(
                    header_name="Message-ID",
                    description=f"Malformed Message-ID format: '{msg_id}'",
                    severity=Severity.LOW,
                )
            )
        return msg_id, anomalies

    def _extract_from(self, msg: EmailMessage) -> Tuple[str, str, str, List[HeaderAnomaly]]:
        anomalies: List[HeaderAnomaly] = []
        raw_froms = msg.get_all("From", [])
        if not raw_froms:
            anomalies.append(
                HeaderAnomaly(
                    header_name="From",
                    description="Missing required From header",
                    severity=Severity.HIGH,
                )
            )
            return "", "", "", anomalies

        if len(raw_froms) > 1:
            anomalies.append(
                HeaderAnomaly(
                    header_name="From",
                    description=f"Multiple From headers detected ({len(raw_froms)}) - possible header injection",
                    severity=Severity.HIGH,
                )
            )

        raw_from = str(raw_froms[0])
        name, addr = parseaddr(raw_from)
        name = self._decode_header_value(name)
        addr = sanitize_header(addr).lower()

        if not addr or "@" not in addr:
            anomalies.append(
                HeaderAnomaly(
                    header_name="From",
                    description=f"Malformed From email address: '{raw_from}'",
                    severity=Severity.HIGH,
                )
            )
            return name, addr, "", anomalies

        domain = addr.split("@")[-1].strip().lower()
        return name, addr, domain, anomalies

    def _extract_single_addr(self, raw_header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not raw_header:
            return None, None
        _, addr = parseaddr(str(raw_header))
        addr = sanitize_header(addr).lower()
        if not addr or "@" not in addr:
            return None, None
        domain = addr.split("@")[-1].strip().lower()
        return addr, domain

    def _extract_addresses(self, raw_list: List[Any]) -> List[str]:
        results: List[str] = []
        for item in raw_list:
            for piece in str(item).split(","):
                _, addr = parseaddr(piece)
                cleaned = sanitize_header(addr).lower()
                if cleaned and "@" in cleaned and cleaned not in results:
                    results.append(cleaned)
        return results

    def _process_received_headers(self, msg: EmailMessage) -> Tuple[List[ReceivedHop], Optional[str]]:
        raw_received = msg.get_all("Received", [])
        hops: List[ReceivedHop] = []
        candidate_ip: Optional[str] = None

        for raw_h in raw_received:
            h_str = sanitize_header(raw_h)
            hop = self._parse_received_hop(h_str)
            hops.append(hop)

        # Originating IP extraction:
        # Traverse from top (most recent receiver) downward.
        # Find the first hop where the sending IP is public/non-reserved or first hop outside trusted receiving boundary.
        for hop in hops:
            if hop.from_ip and is_ip_address(hop.from_ip):
                if not is_private_or_reserved_ip(hop.from_ip):
                    candidate_ip = hop.from_ip
                    break

        # Fallback: if all hops are reserved or private (e.g. lab environment), pick the first valid IP found
        if not candidate_ip:
            for hop in hops:
                if hop.from_ip and is_ip_address(hop.from_ip):
                    candidate_ip = hop.from_ip
                    break

        return hops, candidate_ip

    def _parse_received_hop(self, hop_str: str) -> ReceivedHop:
        by_match = re.search(r"\bby\s+([^\s;]+)", hop_str, re.IGNORECASE)
        from_match = re.search(r"\bfrom\s+([^\s;]+)", hop_str, re.IGNORECASE)
        ip_match = IP_REGEX.search(hop_str)

        by_host = by_match.group(1).lower() if by_match else None
        from_host = from_match.group(1).lower() if from_match else None
        from_ip = ip_match.group(1) if ip_match else None

        # Check if by_host matches configured trusted receivers
        is_trusted = False
        if by_host:
            for tr in self.trusted_receivers:
                if tr in by_host:
                    is_trusted = True
                    break

        return ReceivedHop(
            raw=hop_str,
            by=by_host,
            from_host=from_host,
            from_ip=from_ip,
            is_trusted_receiver=is_trusted,
        )

    def _extract_payloads(self, msg: EmailMessage) -> Tuple[str, str, List[AttachmentInfo]]:
        text_parts: List[str] = []
        html_parts: List[str] = []
        attachments: List[AttachmentInfo] = []

        if msg.is_multipart():
            for part in msg.walk():
                # Skip multipart container parts
                if part.is_multipart():
                    continue

                content_disposition = str(part.get("Content-Disposition", "")).lower()
                filename = part.get_filename()

                is_attachment = ("attachment" in content_disposition) or bool(filename)

                if is_attachment:
                    att_info = self._process_attachment_part(part, filename)
                    if att_info:
                        attachments.append(att_info)
                else:
                    ctype = part.get_content_type()
                    payload = self._get_decoded_part_string(part)
                    if ctype == "text/plain":
                        text_parts.append(payload)
                    elif ctype == "text/html":
                        html_parts.append(payload)
        else:
            ctype = msg.get_content_type()
            payload = self._get_decoded_part_string(msg)
            if ctype == "text/html":
                html_parts.append(payload)
            else:
                text_parts.append(payload)

        return "\n".join(text_parts), "\n".join(html_parts), attachments

    def _get_decoded_part_string(self, part: Any) -> str:
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except Exception as e:
            logger.debug(f"Error decoding text payload: {e}")
            try:
                raw = part.get_payload(decode=False)
                return str(raw) if raw else ""
            except Exception:
                return ""

    def _process_attachment_part(self, part: Any, raw_filename: Optional[str]) -> Optional[AttachmentInfo]:
        decoded_name = self._decode_header_value(raw_filename or "unnamed_attachment")
        content_type = part.get_content_type() or "application/octet-stream"

        try:
            data = part.get_payload(decode=True) or b""
        except Exception as e:
            logger.warning(f"Failed to decode attachment data for {decoded_name}: {e}")
            data = b""

        size_bytes = len(data)
        if size_bytes > self.max_attachment_bytes:
            # Enforce resource bounding
            data = data[: self.max_attachment_bytes]

        sha256 = hashlib.sha256(data).hexdigest()

        # Analyze filename for double extensions and risky extensions
        name_lower = decoded_name.lower()
        parts = [p for p in name_lower.split(".") if p]

        detected_exts = [f".{p}" for p in parts[1:]] if len(parts) > 1 else []
        is_double_ext = len(detected_exts) >= 2

        is_risky = False
        for ext in detected_exts:
            if ext in self.risky_extensions:
                is_risky = True
                break

        return AttachmentInfo(
            filename=decoded_name,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
            is_risky=is_risky,
            is_double_extension=is_double_ext,
            detected_extensions=detected_exts,
        )

    def _extract_urls(self, text_body: str, html_body: str) -> List[URLInfo]:
        urls_dict: Dict[str, URLInfo] = {}

        # 1. Parse plain text URLs
        if text_body:
            for match in URL_REGEX.findall(text_body):
                if len(urls_dict) >= self.max_urls:
                    break
                info = self._analyze_url(match, visible_text=None)
                if info and info.raw_url not in urls_dict:
                    urls_dict[info.raw_url] = info

        # 2. Parse HTML anchors safely with BeautifulSoup
        if html_body:
            try:
                soup = BeautifulSoup(html_body, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    if len(urls_dict) >= self.max_urls:
                        break
                    href = a_tag["href"].strip()
                    visible_text = a_tag.get_text(strip=True)
                    info = self._analyze_url(href, visible_text=visible_text)
                    if info:
                        if info.raw_url in urls_dict:
                            # Update with visible text if not already present
                            if visible_text and not urls_dict[info.raw_url].visible_text:
                                urls_dict[info.raw_url].visible_text = visible_text
                                urls_dict[info.raw_url].domain_mismatch = info.domain_mismatch
                        else:
                            urls_dict[info.raw_url] = info
            except Exception as e:
                logger.debug(f"HTML parsing error during URL extraction: {e}")

        return list(urls_dict.values())

    def _analyze_url(self, raw_url: str, visible_text: Optional[str] = None) -> Optional[URLInfo]:
        if not raw_url or len(raw_url) < 3:
            return None

        # Sanitize
        clean_url = raw_url.strip().strip("<>\"'")

        parsed = urlparse(clean_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Handle schemes without netloc (e.g. data:, javascript:, mailto:)
        if not scheme:
            if clean_url.startswith("//"):
                scheme = "http"
                parsed = urlparse("http:" + clean_url)
                netloc = parsed.netloc.lower()
            elif "@" in clean_url and not clean_url.startswith("http"):
                # mailto or raw email
                return None

        domain = netloc.split(":")[0] if netloc else ""

        is_suspicious_scheme = scheme in ("data", "javascript", "vbscript", "file")
        has_ip = is_ip_address(domain)
        is_short = domain in self.url_shorteners

        is_susp_tld = False
        if domain:
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    is_susp_tld = True
                    break

        # Check text-vs-href mismatch
        domain_mismatch = False
        if visible_text:
            text_cleaned = visible_text.strip().lower()
            # If visible text contains a domain or URL format
            text_domain_match = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", text_cleaned)
            if text_domain_match:
                displayed_domain = text_domain_match.group(1)
                disp_reg = get_registrable_domain(displayed_domain)
                actual_reg = get_registrable_domain(domain)
                if disp_reg and actual_reg and disp_reg != actual_reg:
                    domain_mismatch = True

        return URLInfo(
            raw_url=clean_url,
            scheme=scheme,
            domain=domain,
            visible_text=visible_text,
            is_shortener=is_short,
            has_ip_host=has_ip,
            domain_mismatch=domain_mismatch,
            is_suspicious_tld=is_susp_tld,
            is_suspicious_scheme=is_suspicious_scheme,
        )
