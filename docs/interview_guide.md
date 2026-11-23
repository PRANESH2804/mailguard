# MailGuard Interview Preparation Guide: Technical Defense & Q&A

This guide prepares you to defend **MailGuard** in technical cybersecurity interviews for SOC Analyst, Security Engineering, Detection Engineering, and Internship roles.

---

## 1. 30-Second Elevator Pitch

> *"MailGuard is an open-source defensive email security and detection engineering tool built in Python. It analyzes raw `.eml` messages, evaluates SPF, DKIM, and DMARC with strict and relaxed identifier alignment, executes 17+ behavioral heuristic rules, maps findings to MITRE ATT&CK, computes an explainable 0–100 risk score, derives advisory SOC recommendations (ALLOW, QUARANTINE_AND_REVIEW, ESCALATE_TO_SOC), and generates standardized SOAR incident tickets. It features guaranteed local JSONL persistence, a dual-path Splunk HTTP Event Collector (HEC) integration with production SPL detections and an executive SOC dashboard, and a Flask web UI. The entire suite runs 100% offline with 72 automated unit tests and demonstrated 100% precision and recall across our synthetic ground-truth corpus."*

---

## 2. Technical Interview Questions & Model Answers

### Q1: "Why is DMARC necessary if an organization already has SPF and DKIM deployed?"
**Strong Answer**:
> *"SPF and DKIM operate on different identities than what the user actually sees. SPF authenticates the RFC 5321 Return-Path (envelope sender), while DKIM authenticates the `d=` signing domain. An attacker can easily register their own domain, publish valid SPF and DKIM records, send an email from their server, but display `From: CEO <ceo@company.com>` in the RFC 5322 header. 
> 
> DMARC bridges this gap by introducing **Identifier Alignment**: it requires that either the SPF-authenticated domain or the DKIM-signing domain matches the organizational domain in the visible `From:` header. Furthermore, DMARC allows domain owners to publish policy enforcement instructions (`p=reject` or `p=quarantine`) and receive aggregate XML telemetry (`rua`) on unauthorized infrastructure attempting to spoof their brand."*

---

### Q2: "How does mailing list forwarding affect SPF and DKIM, and how does MailGuard account for this?"
**Strong Answer**:
> *"Email forwarding is one of the classic challenges in email authentication. When an intermediary MTA (like a mailing list or university forwarder) relays a message, the sending IP changes to the forwarder's IP, which breaks SPF. Furthermore, if the mailing list appends a footer (e.g., 'Unsubscribe here') or modifies the subject line, the DKIM body hash (`bh=`) changes, breaking DKIM.
> 
> To solve this in production, forwarders implement **SRS (Sender Rewriting Scheme)** to rewrite the envelope sender and prevent SPF bounces, and **ARC (Authenticated Received Chain - RFC 8617)** to cryptographically attest to the original authentication status before forwarding. In MailGuard, our risk scorer never treats an SPF failure alone as conclusive proof of spoofing; we cross-reference DKIM alignment, look for body hash mismatches versus signature mismatches, and correlate behavioral indicators before assigning a verdict."*

---

### Q3: "Why did you build an explainable heuristic scoring engine rather than training an ML classifier?"
**Strong Answer**:
> *"In a Security Operations Center (SOC), **explainability and determinism are paramount**. If a black-box neural network flags an executive email as phishing with a 0.89 probability, a Tier-1 SOC analyst cannot easily explain why it was flagged or defend that decision to business stakeholders. 
> 
> With MailGuard's deterministic scorer, every single point added to the risk score is mapped to a documented rule ID (e.g. `HEUR-LOOKALIKE-DOMAIN` with +30 weight), raw evidence, and specific MITRE ATT&CK techniques. The report explicitly outputs the top contributing reasons, enabling an analyst to triage and respond within seconds. Furthermore, our rule weights are completely transparent and tunable via `config.yaml` to suit different organizational risk appetites."*

---

### Q4: "What are the limitations of extracting originating IPs from Received headers?"
**Strong Answer**:
> *"Received headers are prepended by each mail server as the email traverses the internet. While the topmost Received header is written by our own trusted gateway and cannot be forged by the sender, any Received headers lower in the chain could have been forged by the attacker before transmission.
> 
> MailGuard's extraction strategy handles this defensively: we inspect the Received headers starting from our trusted receiving gateway boundary downward. The first external hop recording a client connection outside our trusted boundary is identified as the primary candidate originating IP. We also recognize that if the sender used a webmail interface (like Gmail or Microsoft 365), the recorded IP is the provider's server cluster, not the attacker's home IP."*

---

### Q5: "How does MailGuard prevent false positives in lookalike domain detection?"
**Strong Answer**:
> *"A common mistake in typosquatting detection is running string distance algorithms on the entire FQDN including the TLD. For example, comparing `example.com` against `apple.com` yields an 80% similarity ratio simply because they share `.com` and common vowels, causing unacceptable false positives.
> 
> In MailGuard, we engineered a two-stage filter:
> 1. We isolate the Second-Level Domain (SLD) without the TLD (`example` vs `apple`).
> 2. We require both a high RapidFuzz similarity ratio (>= 80%) AND a strict Levenshtein edit distance constraint (<= 2 edits).
> 
> This accurately catches real typo-squatting like `paypa1.com` or `micros0ft.com` while maintaining a 0% false positive rate on legitimate corporate domains."*

---

### Q6: "How did you design the Splunk integration for resilience in production?"
**Strong Answer**:
> *"We implemented a dual-path architecture:
> 1. **Immediate Local Persistence**: MailGuard writes every analysis event as an atomic JSON record to `output/results.jsonl`. If Splunk is down, undergoing maintenance, or unreachable due to network partition, zero telemetry is lost. A Splunk Universal Forwarder can continuously tail this file.
> 2. **Splunk HEC Streaming**: When configured, events are delivered directly over HTTP Event Collector (HEC) with automated retries and exponential backoff.
> 
> Furthermore, all Splunk telemetry conforms to CIM (Common Information Model) field aliases (`src`, `src_user`, `message_subject`), allowing our custom SPL detections and dashboard to correlate seamlessly with existing SOC alert pipelines."*
