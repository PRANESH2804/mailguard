# How MailGuard Works: Deep-Dive Technical Guide

This document explains the foundational email authentication protocols, heuristic detection engineering principles, and SOC SIEM telemetry implemented in **MailGuard**.

---

## 1. The Core Email Authentication Triad

Traditional SMTP (RFC 821, updated in RFC 5321) was created without built-in identity verification. Any client could connect to an open mail transfer agent (MTA) and specify arbitrary addresses in the envelope and message headers. To counter identity deception, the security community standardized three complementary protocols:

```
+------------------------------------------------------------------------------------+
|                                 The From: Header                                   |
|                        "Alice Smith" <alice@example.com>                           |
+------------------------------------------------------------------------------------+
             |                                              |
             v                                              v
+-----------------------------+               +-----------------------------+
|    SPF (RFC 7208)           |               |   DKIM (RFC 6376)           |
| Validates sending server IP |               | Cryptographically verifies  |
| against Return-Path domain. |               | message body and headers.   |
+-----------------------------+               +-----------------------------+
             \                                              /
              \                                            /
               v                                          v
      +------------------------------------------------------------+
      |                      DMARC (RFC 7489)                      |
      |   Validates that SPF and/or DKIM align with the visible    |
      |   From: header domain, and enforces domain owner policy.   |
      +------------------------------------------------------------+
```

---

## 2. Sender Policy Framework (SPF) — RFC 7208

### Concept & Mechanics
SPF allows domain owners to publish a DNS TXT record declaring which IP addresses and networks are authorized to send mail on behalf of their domain:
```dns
example.com.  IN  TXT  "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all"
```

### Evaluated Identity
SPF evaluates the **RFC 5321 Return-Path (Envelope Sender)** or the **HELO/EHLO identity**, NOT the visible `From:` header. This is a critical distinction: an attacker can send an email with `Return-Path: attacker@evil.com` (which has valid SPF) while displaying `From: CEO <ceo@target.com>`. Without DMARC, SPF alone passes!

### SPF Qualifiers & Mechanisms
- `ip4:` / `ip6:` — Authorizes specific CIDR ranges.
- `a` — Authorizes the domain's A record IP.
- `mx` — Authorizes the domain's MX exchange IPs.
- `include:` — Evaluates another domain's SPF record.
- `redirect=` — Delegates evaluation entirely to another domain.
- `all` — Terminal mechanism specifying the default action:
  - `+all` (Pass): Permits any IP (insecure).
  - `-all` (Fail / HardFail): Explicitly rejects unlisted IPs.
  - `~all` (SoftFail): Marks unlisted IPs as suspicious but requests delivery.
  - `?all` (Neutral): Expresses no policy.

### MailGuard Implementation
MailGuard wraps `pyspf` via `spf.check2()`, intercepting DNS queries via dependency-injected DNS resolvers (`BaseDNSResolver`). In offline mode, the resolver serves local JSON fixtures, guaranteeing deterministic offline testing without network queries.

---

## 3. DomainKeys Identified Mail (DKIM) — RFC 6376

### Concept & Mechanics
DKIM adds a cryptographic digital signature to the message headers, verifying that:
1. The message originated from the authorized signing domain (`d=`).
2. The signed headers and message body have not been altered in transit.

### Structure of `DKIM-Signature` Header
```email
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=example.com;
 s=s1; t=1793169642; h=from:to:subject:date;
 bh=x/N8/ivRfGMxF56p8/vkrTaHlPadGijHRWz0MB878Wk=;
 b=l5S97yShZXzma0JRCy5HeVG3RDBB0BEmNgaMcSX5n3L7Kdra6d...
```
- `d=`: Signing domain.
- `s=`: Selector (identifies which public key record to query at `<selector>._domainkey.<domain>`).
- `a=`: Algorithm (e.g., `rsa-sha256`, `ed25519-sha256`).
- `c=`: Canonicalization algorithm for headers and body (`relaxed` or `simple`).
- `bh=`: Base64 SHA-256 hash of the canonicalized message body.
- `b=`: The cryptographic signature calculated over the canonicalized header fields and `bh=`.
- `x=`: Optional Unix timestamp expiration.

### Verification Process in MailGuard
1. Parse every `DKIM-Signature` header in the message.
2. Query `<selector>._domainkey.<domain>` for the public key TXT record (`v=DKIM1; k=rsa; p=...`).
3. Hash the canonicalized body and compare with `bh=`. If they disagree, flag `body_hash_status = FAIL`.
4. Decrypt signature `b=` using the public key and verify the header hash.
5. Check expiration tag `x=`: if `time.time() > exp_ts`, flag as expired.
6. Verify against original raw message bytes (`msg.raw_bytes`).

---

## 4. DMARC & Identifier Alignment — RFC 7489

### The Problem DMARC Solves
- SPF validates only `Return-Path` (envelope).
- DKIM validates only `d=` (signer), which can be any third-party domain.
- Neither protocol guarantees that the visible `From:` domain shown to the end user was authenticated!

### DMARC Policy Evaluation
DMARC links SPF and DKIM directly to the visible `RFC 5322 From:` domain via **Identifier Alignment**:

A message passes DMARC if **at least one** of these conditions holds:
1. **SPF Passes** AND the `Return-Path` domain **aligns** with the visible `From:` domain.
2. **DKIM Passes** AND the `d=` signing domain **aligns** with the visible `From:` domain.

### Alignment Modes:
- **Strict (`s`)**: Exact FQDN match (`example.com` == `example.com`).
- **Relaxed (`r`, Default)**: Organizational / Registrable domain match (`sub.example.com` aligns with `example.com`).

### DMARC Policies:
- `p=none`: Monitor mode; request receiver to take no restrictive action.
- `p=quarantine`: Request receiver to treat unauthenticated mail as spam/quarantine.
- `p=reject`: Request receiver to reject the message outright at the SMTP gateway.
- `sp=`: Policy for subdomains (if omitted, falls back to `p=`).
- `pct=`: Percentage of messages subject to policy enforcement (0–100).

---

## 5. Defensive MIME & URL Parsing Controls

1. **Resource Bounding**: Rejects files larger than 25MB and limits attachments to 10MB to prevent memory exhaustion and zip-bomb denial of service.
2. **Zero Remote Requests**: URLs and images are never fetched, preventing attacker tracking pixels and SSRF.
3. **Safe HTML Parsing**: BeautifulSoup extracts anchor tags and visible text in memory without rendering.
4. **Anchor Mismatch Detection**: Compares visible anchor text against the `href` target domain. If visible text says `paypal.com` but destination is `evil-site.com`, a high-severity indicator is triggered.

---

## 6. Explainable Detection & Scorer

Rather than relying on an opaque machine-learning model, MailGuard implements an explainable, deterministic detection engine:
- Each finding carries a rule identifier (e.g. `HEUR-LOOKALIKE-DOMAIN`), explicit severity, points weight, human explanation, and raw evidence.
- Correlation dampening prevents artificial score inflation: related brand markers are capped at 45 points combined.
- Unknown authentication states (e.g. temporary DNS timeout) are handled separately from hard cryptographic failures.
- Top contributing reasons are output directly into the report and Splunk event, allowing SOC analysts to understand the rationale in seconds.
