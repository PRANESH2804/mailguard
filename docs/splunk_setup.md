# Splunk SIEM Integration & Setup Guide

This guide details how to integrate **MailGuard** with Splunk Enterprise, Splunk Cloud, or a local Docker/Homelab Splunk instance.

---

## 1. Prerequisites

- Splunk Enterprise 9.0+ or Splunk Cloud.
- Administrative access to create indexes, configure HTTP Event Collector (HEC), and import Simple XML dashboards.
- Network access from the MailGuard sensor to Splunk HEC port `8088` (or default management port).

---

## 2. Step 1: Create the Dedicated Security Index

It is recommended to store MailGuard analysis telemetry in a dedicated index:

### Via Splunk Web:
1. Navigate to **Settings > Indexes**.
2. Click **New Index**.
3. Set **Index Name**: `security_lab`.
4. Set **Index Data Type**: Events.
5. Click **Save**.

### Via Splunk CLI:
```bash
/opt/splunk/bin/splunk add index security_lab -auth admin:YourPassword
```

---

## 3. Step 2: Configure HTTP Event Collector (HEC)

### Enable HEC Globally:
1. Go to **Settings > Data Inputs > HTTP Event Collector**.
2. Click **Global Settings**.
3. Toggle **All Tokens** to `Enabled`.
4. Note the HTTP Port Number (default: `8088`).
5. (Optional) Toggle **Enable SSL** based on your environment.
6. Click **Save**.

### Create MailGuard HEC Token:
1. Click **New Token**.
2. Name: `mailguard_hec_token`.
3. Source name override: `mailguard`.
4. Click **Next**.
5. Set **Source Type**: `mailguard:analysis`.
6. Set **Default Index**: `security_lab`.
7. Click **Review**, then **Submit**.
8. Copy the generated **Token Value** (e.g. `12345678-1234-1234-1234-123456789abc`).

---

## 4. Step 3: Configure Environment Variables

Export the credentials on the system running MailGuard:

```bash
export SPLUNK_HEC_URL="http://localhost:8088/services/collector/event"
export SPLUNK_HEC_TOKEN="12345678-1234-1234-1234-123456789abc"
export SPLUNK_INDEX="security_lab"
export SPLUNK_VERIFY_SSL="false"
```

Or add them to your local `.env` file (see `.env.example`).

---

## 5. Step 4: Verify HEC Ingestion

### Test with cURL:
```bash
curl -k http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
  -d '{"sourcetype": "mailguard:analysis", "index": "security_lab", "event": {"message": "HEC test verification"}}'
```
Expected response:
```json
{"text":"Success","code":0}
```

### Test with MailGuard CLI:
```bash
mailguard analyze samples/spoofed/spoofed_01_spf_dmarc_fail.eml --offline --send-to-splunk
```

---

## 6. Step 5: Deploy Props & Transforms

Deploy the field extractions and CIM aliases provided in `splunk/props.conf`:

```bash
sudo mkdir -p /opt/splunk/etc/apps/mailguard/default
sudo cp splunk/props.conf /opt/splunk/etc/apps/mailguard/default/
sudo cp splunk/transforms.conf /opt/splunk/etc/apps/mailguard/default/
sudo cp splunk/saved_searches.conf /opt/splunk/etc/apps/mailguard/default/
/opt/splunk/bin/splunk restart
```

---

## 7. Step 6: Import Dashboard XML

1. Open **Splunk Web**.
2. Click **Search & Reporting > Dashboards > Create New Dashboard**.
3. Title: `MailGuard: Email Authentication & Spoofing Monitoring`.
4. Click **Create**.
5. Switch to **Source** mode (top right button).
6. Replace the boilerplate with the complete contents of `splunk/dashboard.xml`.
7. Click **Save**.

---

## 8. Troubleshooting Common Issues

| Symptom | Probable Cause | Remediation |
| :--- | :--- | :--- |
| `HTTP 401 Unauthorized` | Invalid or expired token | Verify `SPLUNK_HEC_TOKEN` matches the active token in Splunk Web. |
| `HTTP 403 Forbidden` | Index restriction | Ensure `security_lab` is added to **Selected Indexes** for the token. |
| `Connection refused (port 8088)` | HEC disabled globally | Go to **Settings > Data Inputs > HEC > Global Settings** and enable HEC. |
| `SSLError: certificate verify failed` | Self-signed certificate | Set `SPLUNK_VERIFY_SSL=false` in environment or configure trusted CA root. |
| `Events missing in index` | Wrong sourcetype or time skew | Search `index=_internal sourcetype=splunkd_hec` for ingestion errors. |
