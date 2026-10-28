# MailGuard Splunk SIEM Integration Guide

This directory provides the production-grade Splunk App configurations, inputs, field extractions, detection searches, and SOC dashboard for **MailGuard**.

---

## 1. Overview & Architecture

MailGuard streams structured JSON security events to Splunk via two redundant methods:
1. **Splunk HTTP Event Collector (HEC)**: Real-time, network-based ingestion into index `security_lab` with sourcetype `mailguard:analysis`.
2. **Local JSONL Event Monitor**: Continuous fallback persistence to `output/results.jsonl`, monitored via Splunk Universal Forwarder or local file monitor.

```
+-------------------------------------------------------------------+
|                        MailGuard Engine                           |
|  (Parser -> SPF -> DKIM -> DMARC -> Heuristics -> Risk Scorer)    |
+-------------------------------------------------------------------+
             |                                    |
             v (HTTP POST)                        v (Append)
  +----------------------+            +-----------------------+
  |   Splunk HEC         |            | output/results.jsonl  |
  |   Port 8088          |            | (Offline Audit Log)   |
  +----------------------+            +-----------------------+
             |                                    |
             +-----------------> <----------------+
                               |
                               v
                     +--------------------+
                     | Splunk Enterprise  |
                     | Index: security_lab|
                     | Sourcetype:        |
                     | mailguard:analysis |
                     +--------------------+
```

---

## 2. Ingest Schema & Field Catalog

Every event contains the following normalized fields:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Time of email processing |
| `message_id` | String | RFC 5322 Message-ID header |
| `from_address` | String | Sender email address |
| `from_domain` | String | Registrable domain from From header |
| `return_path` | String | Envelope sender address |
| `originating_ip` | String | Candidate external sender IP |
| `recipients{}` | Array of Strings | Message recipients |
| `spf.status` | String | `PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `NONE`, `PERMERROR` |
| `dkim.overall_status` | String | `PASS`, `FAIL`, `NONE`, `TEMPERROR` |
| `dmarc.status` | String | `PASS`, `FAIL`, `NONE`, `PERMERROR` |
| `alignment.spf_aligned_relaxed` | Boolean | SPF organizational domain alignment |
| `alignment.dkim_aligned_relaxed` | Boolean | DKIM organizational domain alignment |
| `risk_score` | Integer (0-100) | Clamped composite risk score |
| `verdict` | String | `LEGITIMATE`, `SUSPICIOUS`, `SPOOFED` |
| `top_reasons{}` | Array of Strings | Top factor explanations with weights |
| `mitre_techniques{}` | Array of Objects | Mapped MITRE ATT&CK techniques |
| `urls{}` | Array of Objects | Extracted URLs and indicators |
| `attachments{}` | Array of Objects | Attachment names, MIME types, and SHA-256 hashes |

---

## 3. Production SPL Detection Queries

### Detection A: High-Risk Suspected Spoofed Emails by Domain
- **Purpose**: Identifies external domains generating clusters of emails that fail SPF/DKIM/DMARC.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" verdict="SPOOFED"
  | stats count, values(subject) as subjects, values(originating_ip) as src_ips, avg(risk_score) as avg_risk by from_domain
  | eval avg_risk=round(avg_risk, 1)
  | sort - count
  ```
- **Severity**: High (4)
- **SOC Analyst Action**: Verify if domain is an impersonated corporate partner. Add sending IPs to gateway blocklist if confirmed hostile.
- **MITRE Technique**: `T1672` (Subvert Trust Controls: Email Spoofing)
- **Limitations**: In rare cases, forwarding mail servers without SRS can cause SPF failures.

---

### Detection B: Authentication Failure Spikes Over Time
- **Purpose**: Detects widespread email authentication degradation or misconfiguration.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis"
  | eval spf_fail=if('spf.status'!="PASS", 1, 0), dkim_fail=if('dkim.overall_status'!="PASS", 1, 0), dmarc_fail=if('dmarc.status'!="PASS", 1, 0)
  | timechart span=1h sum(spf_fail) as total_spf_failures, sum(dkim_fail) as total_dkim_failures, sum(dmarc_fail) as total_dmarc_failures
  ```
- **Severity**: Medium (3)
- **SOC Analyst Action**: Investigate whether an enterprise DNS change broken legitimate email deliverability or if an inbound spam wave occurred.
- **MITRE Technique**: `T1672`
- **Limitations**: Requires historical baseline to establish normal operational thresholds.

---

### Detection C: Typosquatting and Lookalike Domain Campaigns
- **Purpose**: Detects spearphishing attacks utilizing visual lookalikes, homoglyphs, or combosquatting.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" "heuristics{}.id"="HEUR-LOOKALIKE-DOMAIN" OR "heuristics{}.id"="HEUR-BRAND-COMBOSQUATTING"
  | stats count, values(from_address) as senders, values(subject) as subjects, values(heuristics{}.evidence) as evidence by from_domain
  | sort - count
  ```
- **Severity**: High (4)
- **SOC Analyst Action**: Check recipient mailboxes for opened messages; submit typosquatted domain to registrar abuse desk.
- **MITRE Technique**: `T1672`, `T1566.002`
- **Limitations**: Brands not in `config.yaml` trusted brands list will not trigger this rule.

---

### Detection D: Dangerous or Double-Extension Attachments
- **Purpose**: Flags inbound initial access attempts carrying executables, scripts, or masked double extensions.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" "attachments{}.is_risky"=true OR "attachments{}.is_double_extension"=true
  | mvexpand "attachments{}"
  | search "attachments{}.is_risky"=true OR "attachments{}.is_double_extension"=true
  | table _time, from_address, recipients{}, "attachments{}.filename", "attachments{}.sha256", "attachments{}.detected_extensions{}", risk_score, verdict
  ```
- **Severity**: Critical (5)
- **SOC Analyst Action**: Isolate recipient workstation if email was delivered. Query EDR for observed attachment SHA-256 hash.
- **MITRE Technique**: `T1566.001` (Phishing: Spearphishing Attachment)
- **Limitations**: Password-protected ZIP archives cannot have nested file extensions inspected statically.

---

### Detection E: Most Targeted Internal Recipients
- **Purpose**: Identifies specific employees or departments receiving high concentrations of suspicious lures.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" verdict IN ("SUSPICIOUS", "SPOOFED")
  | mvexpand recipients{}
  | stats count, values(from_address) as attackers, dc(from_domain) as unique_sender_domains by recipients{}
  | rename recipients{} as target_user
  | sort - count
  | head 20
  ```
- **Severity**: Medium (3)
- **SOC Analyst Action**: Provide targeted security awareness training or apply elevated mailbox protection policies.
- **MITRE Technique**: `T1566`
- **Limitations**: Distribution lists (`all@company.com`) may skew individual targeted counts.

---

### Detection F: Persistent Malicious Sender IP
- **Purpose**: Identifies adversarial MTAs attempting to send malicious mail under multiple different identities.
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" verdict IN ("SUSPICIOUS", "SPOOFED") originating_ip=*
  | stats count, dc(from_domain) as spoofed_domains, values(subject) as subjects, values(from_address) as senders by originating_ip
  | where count >= 2
  | sort - count
  ```
- **Severity**: High (4)
- **SOC Analyst Action**: Add originating IP to perimeter firewall or mail gateway reputation reject list.
- **MITRE Technique**: `T1672`
- **Limitations**: Cloud shared email sending services (e.g., SendGrid, Mailchimp) may share public IPs across multiple tenants.

---

### Detection G: Critical Severity Email Requiring Immediate SOC Triage
- **Purpose**: Real-time alert for incoming emails scoring in the high-confidence spoofing range (>= 70).
- **SPL Query**:
  ```spl
  index=security_lab sourcetype="mailguard:analysis" risk_score >= 70
  | table _time, message_id, from_address, recipients{}, subject, risk_score, "spf.status", "dkim.overall_status", "dmarc.status", top_reasons{}
  | sort - risk_score
  ```
- **Severity**: Critical (5)
- **SOC Analyst Action**: Trigger automated SOAR playbook to purge message from inbox; alert targeted users.
- **MITRE Technique**: `T1672`, `T1566`
- **Limitations**: Dependent on correct scoring weights calibration.

---

## 4. Dashboard Installation

1. Log into **Splunk Web**.
2. Navigate to **Search & Reporting > Dashboards > Create New Dashboard**.
3. Set Dashboard Title: `MailGuard: Email Authentication & Spoofing Monitoring`.
4. Switch to **Source Code (XML)** view.
5. Paste the complete contents of `splunk/dashboard.xml`.
6. Click **Save** and verify all 6 panels load with sample events.
