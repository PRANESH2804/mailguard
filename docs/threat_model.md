# MailGuard Threat Model & Security Architecture

This document presents the defensive threat model for **MailGuard**, detailing assets, threat actors, trust boundaries, attack surfaces, and engineered mitigations.

---

## 1. Assets & Trust Boundaries

### Critical Assets:
1. **Analyst Workstation & Server Integrity**: Prevention of remote code execution (RCE) via untrusted email attachments or malicious inputs.
2. **Analysis Integrity**: Protection against adversarial evasion, forged authentication headers, and score manipulation.
3. **SIEM Credentials**: Splunk HEC tokens, API keys, and internal network telemetry.
4. **Data Privacy (PII)**: Protection of employee recipient addresses, internal correspondence, and confidential attachments.

### Trust Boundaries:
- **Untrusted Input Boundary**: Raw `.eml` files, email headers, MIME payloads, HTML links, and attachment bytes originating from external untrusted networks.
- **Internal Security Boundary**: The MailGuard parser, scoring engine, and local runtime environment.
- **External Monitoring Boundary**: The Splunk SIEM ingestion pipeline and optional threat intelligence APIs.

```
       UNTRUSTED INTERNET
  +--------------------------+
  | Inbound Phishing Email   |
  | (Headers, Body, Payloads)|
  +--------------------------+
               |
  ======== TRUST BOUNDARY 1: Strict Ingestion Validation ========
               |
  +--------------------------+
  | MailGuard Defensive Core |
  | (MIME Parser, Cryptography|
  |  Heuristics, Scorer)     |
  +--------------------------+
               |
  ======== TRUST BOUNDARY 2: Protected Output & Forwarding ======
               |
  +--------------------------+
  | Splunk SIEM / Local Logs |
  +--------------------------+
```

---

## 2. Threat Actor Personas

1. **Mass Spammer**: Automated botnets blasting high-volume affiliate scams and credential harvesting with invalid or absent SPF/DKIM records.
2. **Business Email Compromise (BEC) Adversary**: Sophisticated fraudster using display-name spoofing, lookalike domains (`examp1e.com`), and reply-to manipulation to divert invoice payments.
3. **State-Sponsored / Advanced Persistent Threat (APT)**: Sophisticated spearphishing operator employing weaponized attachments, double extensions, and homoglyph domains to bypass enterprise secure email gateways (SEGs).

---

## 3. Attack Surfaces & Engineered Mitigations

### A. Forged Authentication-Results Headers
- **Threat**: An adversary prepends a forged `Authentication-Results: spf=pass dkim=pass dmarc=pass` header inside their malicious `.eml` file before transmission.
- **Impact**: Naive parsers that trust pre-existing headers will classify spoofed mail as legitimate.
- **MailGuard Mitigation**:
  - Pre-existing `Authentication-Results` headers are treated as **untrusted evidence**.
  - MailGuard actively re-evaluates SPF and re-verifies DKIM cryptographic signatures from raw bytes.
  - If a header claims PASS but does not originate from a configured trusted receiving gateway in `trusted_receivers`, MailGuard triggers rule `HEUR-UNTRUSTED-AUTH-HEADER` (+15 risk score penalty).

### B. Malformed MIME & Resource Exhaustion (Zip Bombs / Decompression Bombs)
- **Threat**: Attacker sends a multi-gigabyte message, deeply nested MIME parts, or an oversized attachment designed to crash Python or exhaust memory (DoS).
- **MailGuard Mitigation**:
  - Strict input size validation before reading bytes: files over `limits.max_message_bytes` (25MB) are rejected immediately.
  - Attachments larger than `limits.max_attachment_bytes` (10MB) are bounded and truncated.
  - URL parsing limits analysis to the first 100 links per email.

### C. Malicious Attachment Execution
- **Threat**: Attachment contains a malicious binary, script (`.vbs`, `.ps1`), or macro document (`.xlsm`).
- **MailGuard Mitigation**:
  - MailGuard **never opens, unpacks, or executes attachments**.
  - Only cryptographic hashes (SHA-256), MIME types, and filenames are inspected in memory.
  - Double extensions (`.pdf.exe`) and executable extensions trigger critical severity heuristics.

### D. Zero-Remote Assets & SSRF Prevention
- **Threat**: HTML emails contain external images (`<img src="http://attacker.com/tracking.png">`) or external stylesheets intended to leak the analyst's IP address or trigger Server-Side Request Forgery.
- **MailGuard Mitigation**:
  - MailGuard performs **zero network requests for email content**.
  - BeautifulSoup extracts anchor tags and text purely in memory.
  - Email HTML is **never rendered directly in the browser**.

### E. Splunk HEC Credential Exposure
- **Threat**: Leaking `SPLUNK_HEC_TOKEN` into console logs, terminal output, git repositories, or exported JSON reports.
- **MailGuard Mitigation**:
  - Credentials are read **only from environment variables** (`SPLUNK_HEC_TOKEN`), never hardcoded in YAML or Python code.
  - The token is placed exclusively in the outgoing HTTP Authorization header.
  - All logging and serialization explicitly omit the token.

### F. Web Interface Vulnerabilities (CSRF & XSS)
- **Threat**: Attacker tricks an analyst into submitting an arbitrary payload via Cross-Site Request Forgery, or executes scripts via Stored XSS in the email subject or From header.
- **MailGuard Mitigation**:
  - CSRF tokens are cryptographically generated and enforced on all file uploads.
  - All dynamic data rendered in HTML is sanitized through `html.escape()` or Jinja2 automatic escaping.
  - Defensive HTTP response headers are enforced: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self' 'unsafe-inline'`.

---

## 4. Privacy & PII Handling

- **Indicator Minimization**: When optional external enrichment (VirusTotal, AbuseIPDB) is enabled, MailGuard **never sends email message bodies, subjects, or attachments**; it transmits only the isolated indicator (file SHA-256 or external IP).
- **Recipient Anonymization**: Configurable support for recipient masking or hashing before Splunk ingestion to comply with GDPR/HIPAA requirements.
