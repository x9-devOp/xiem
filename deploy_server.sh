#!/usr/bin/env bash
# Server-side deployment for XIEM phases 2-6.
# Usage (from Mac): ssh spravce@xiem.x9.cz 'bash -s' < deploy_server.sh
# Usage (on server): bash deploy_server.sh

set -euo pipefail

FLASK_DIR="/var/www/flask_xiem"
VENV="$FLASK_DIR/venv"
XIEM_ENV="/etc/xiem/env"
KEY_PATH="/etc/xiem/signing_key.pem"
PUBKEY_PATH="/etc/xiem/signing_pubkey.pem"
MIGRATION="$FLASK_DIR/migrations/001_phase1.sql"
AGENT_DIR="$FLASK_DIR/agent"
SERVICE_FILE="/etc/systemd/system/xiem-api.service"

# --- Step 1: RSA signing key ---
echo "==> [1/5] RSA signing key"
if sudo test -f "$KEY_PATH"; then
  echo "    Key already exists at $KEY_PATH, skipping generation."
else
  sudo mkdir -p /etc/xiem
  sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_PATH"
  sudo chmod 600 "$KEY_PATH"
  sudo openssl rsa -in "$KEY_PATH" -pubout -out "$PUBKEY_PATH"
  sudo chmod 644 "$PUBKEY_PATH"
  echo "    Generated $KEY_PATH + $PUBKEY_PATH"
fi

# Expose key path to Flask via env file
if ! sudo grep -q "XIEM_SIGNING_KEY" "$XIEM_ENV" 2>/dev/null; then
  echo "XIEM_SIGNING_KEY=$KEY_PATH" | sudo tee -a "$XIEM_ENV" > /dev/null
  echo "    Added XIEM_SIGNING_KEY to $XIEM_ENV"
fi

# Inject into systemd service unit if not already there
if sudo test -f "$SERVICE_FILE" && ! sudo grep -q "XIEM_SIGNING_KEY" "$SERVICE_FILE"; then
  sudo sed -i "/XIEM_DB_DSN/a Environment=XIEM_SIGNING_KEY=$KEY_PATH" "$SERVICE_FILE"
  sudo systemctl daemon-reload
  echo "    Injected XIEM_SIGNING_KEY into $SERVICE_FILE"
fi

# --- Step 2: Python cryptography library ---
echo "==> [2/5] pip install cryptography"
sudo "$VENV/bin/pip" install --quiet cryptography
echo "    OK"

# --- Step 3: DB migration ---
echo "==> [3/5] DB migration"
if [ ! -f "$MIGRATION" ]; then
  echo "    ERROR: $MIGRATION not found" >&2
  exit 1
fi
DSN=$(sudo grep XIEM_DB_DSN "$XIEM_ENV" | cut -d= -f2-)
psql "$DSN" -f "$MIGRATION"
echo "    Migration applied."

# --- Step 4: Agent binary directory ---
echo "==> [4/5] Agent binary directory"
sudo mkdir -p "$AGENT_DIR"
sudo chown www-data:www-data "$AGENT_DIR"
echo "    $AGENT_DIR ready"

# --- Step 5: Restart Flask ---
echo "==> [5/5] Restart Flask service"
sudo systemctl restart xiem-api
sleep 2
sudo systemctl is-active --quiet xiem-api && echo "    xiem-api is running." || {
  echo "    ERROR: xiem-api failed to start, check logs:" >&2
  sudo journalctl -u xiem-api -n 30 --no-pager >&2
  exit 1
}

echo ""
echo "==> Deploy complete."
echo "    Next: build & upload agent binary with ./build_agent.sh"
echo "    Then: install agent on Windows endpoints (manual step 6)"
