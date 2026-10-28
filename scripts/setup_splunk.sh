#!/usr/bin/env bash
# ==============================================================================
# MailGuard Splunk Onboarding Script
# Automates index creation, HEC token provisioning, and app installation.
# ==============================================================================

set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
INDEX_NAME="security_lab"
APP_NAME="mailguard"
HEC_TOKEN_NAME="mailguard_hec_token"

echo "================================================================="
echo "MailGuard: Splunk SIEM Integration Setup"
echo "================================================================="

if [ ! -d "$SPLUNK_HOME" ]; then
    echo "[!] Splunk directory not found at $SPLUNK_HOME."
    echo "[*] If running Splunk in Docker or a non-standard directory, set SPLUNK_HOME."
    echo "[*] Example: SPLUNK_HOME=/opt/splunk ./setup_splunk.sh"
    echo "[*] Providing standalone configuration instructions below..."
    exit 0
fi

SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"

if [ ! -x "$SPLUNK_BIN" ]; then
    echo "[!] Splunk binary not found at $SPLUNK_BIN"
    exit 1
fi

echo "[1/4] Ensuring index '${INDEX_NAME}' exists..."
if ! "$SPLUNK_BIN" list index "$INDEX_NAME" >/dev/null 2>&1; then
    echo "[*] Adding index '${INDEX_NAME}'..."
    "$SPLUNK_BIN" add index "$INDEX_NAME" -auth admin:changeme || true
else
    echo "[✓] Index '${INDEX_NAME}' already exists."
fi

echo "[2/4] Deploying MailGuard Splunk App to ${SPLUNK_HOME}/etc/apps/${APP_NAME}..."
APP_DIR="${SPLUNK_HOME}/etc/apps/${APP_NAME}"
mkdir -p "${APP_DIR}/default" "${APP_DIR}/metadata"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

cp "$REPO_DIR/splunk/props.conf" "${APP_DIR}/default/"
cp "$REPO_DIR/splunk/transforms.conf" "${APP_DIR}/default/"
cp "$REPO_DIR/splunk/saved_searches.conf" "${APP_DIR}/default/"
mkdir -p "${APP_DIR}/default/data/ui/views"
cp "$REPO_DIR/splunk/dashboard.xml" "${APP_DIR}/default/data/ui/views/"

cat << 'EOF' > "${APP_DIR}/default/app.conf"
[install]
is_configured = 1
state = enabled

[ui]
is_visible = 1
label = MailGuard Email Security

[launcher]
author = Pranesh
description = Defensive Email Authentication & Spoofing Analyzer SIEM App
version = 1.0.0
EOF

cat << 'EOF' > "${APP_DIR}/metadata/default.meta"
[]
export = system
EOF

echo "[✓] MailGuard App files copied successfully."

echo "[3/4] Enabling HTTP Event Collector (HEC)..."
"$SPLUNK_BIN" http-event-collector enable -uri https://localhost:8089 -auth admin:changeme || true

echo "[4/4] Creating HEC Token '${HEC_TOKEN_NAME}'..."
"$SPLUNK_BIN" http-event-collector create "$HEC_TOKEN_NAME" \
    -uri https://localhost:8089 \
    -auth admin:changeme \
    -index "$INDEX_NAME" \
    -indexes "$INDEX_NAME" \
    -sourcetype "mailguard:analysis" || true

echo ""
echo "================================================================="
echo "[✓] Setup complete! Restart Splunk to apply configuration:"
echo "    ${SPLUNK_BIN} restart"
echo "================================================================="
