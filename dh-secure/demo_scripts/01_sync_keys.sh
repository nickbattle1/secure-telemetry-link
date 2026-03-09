#!/bin/bash
# Helper script to sync public keys between laptop (Alice) and Pi (Bob)

# --- CONFIGURE THESE IF NEEDED ---
PI_USER="flight"
PI_HOST="192.168.0.45"
PI_PROJECT_DIR="/home/flight/dh-secure"
LOCAL_KEYS_DIR="keys"
REMOTE_KEYS_DIR="$PI_PROJECT_DIR/keys"
# ---------------------------------

set -e

echo "=== Secure Telemetry: Public Key Sync ==="
echo "Pi user:       $PI_USER"
echo "Pi host:       $PI_HOST"
echo "Pi project:    $PI_PROJECT_DIR"
echo "Local keys dir: $LOCAL_KEYS_DIR"
echo

# 1. Sanity check local Alice public key
if [ ! -f "$LOCAL_KEYS_DIR/alice_ed25519_pub.pem" ]; then
  echo "ERROR: $LOCAL_KEYS_DIR/alice_ed25519_pub.pem not found."
  echo "Run:  bash demo_scripts/01_generate_keys.sh alice"
  exit 1
fi

# 2. Copy Alice's public key to Pi
echo "[1/3] Copying Alice's public key -> Pi..."
scp "$LOCAL_KEYS_DIR/alice_ed25519_pub.pem" \
    "$PI_USER@$PI_HOST:$REMOTE_KEYS_DIR/"

echo "[2/3] Ensuring Bob's public key exists on Pi..."
echo "      (If this fails, run on Pi: bash demo_scripts/01_generate_keys.sh bob)"
ssh "$PI_USER@$PI_HOST" "test -f '$REMOTE_KEYS_DIR/bob_ed25519_pub.pem'"

# 3. Copy Bob's public key back from Pi to laptop
echo "[3/3] Copying Bob's public key -> laptop..."
scp "$PI_USER@$PI_HOST:$REMOTE_KEYS_DIR/bob_ed25519_pub.pem" \
    "$LOCAL_KEYS_DIR/"

echo
echo "✓ Public key sync complete."
echo "Local keys/ now contains:"
ls -1 "$LOCAL_KEYS_DIR"/alice_ed25519_pub.pem "$LOCAL_KEYS_DIR"/bob_ed25519_pub.pem 2>/dev/null || true

#running this script
: <<'COMMENT'
chmod +x demo_scripts/01_sync_keys.sh
bash demo_scripts/01_sync_keys.sh
COMMENT
