#!/bin/bash
# Generate Ed25519 static identity keys for Alice and/or Bob

ROLE="${1:-both}"   # alice | bob | both (default: both)

echo "Generating Ed25519 identity keys (role: $ROLE)..."
echo ""

ROLE="$ROLE" python3 - << 'EOF'
import os
from pathlib import Path
from crypto_suite import CryptoSuite

role = os.environ.get("ROLE", "both").lower()
keys_dir = Path("keys")
keys_dir.mkdir(exist_ok=True)

def gen_alice():
    print("Generating Alice's Ed25519 key pair...")
    alice_priv, alice_pub = CryptoSuite.generate_ed25519_keypair()
    priv_path = keys_dir / "alice_ed25519_priv.pem"
    pub_path  = keys_dir / "alice_ed25519_pub.pem"
    CryptoSuite.save_ed25519_private_key(alice_priv, priv_path)
    CryptoSuite.save_ed25519_public_key(alice_pub, pub_path)
    os.chmod(priv_path, 0o600)
    print(f"  - Saved private key to {priv_path}")
    print(f"  - Saved public key  to {pub_path}")

def gen_bob():
    print("\nGenerating Bob's Ed25519 key pair...")
    bob_priv, bob_pub = CryptoSuite.generate_ed25519_keypair()
    priv_path = keys_dir / "bob_ed25519_priv.pem"
    pub_path  = keys_dir / "bob_ed25519_pub.pem"
    CryptoSuite.save_ed25519_private_key(bob_priv, priv_path)
    CryptoSuite.save_ed25519_public_key(bob_pub, pub_path)
    os.chmod(priv_path, 0o600)
    print(f"  - Saved private key to {priv_path}")
    print(f"  - Saved public key  to {pub_path}")

if role in ("alice", "both"):
    gen_alice()
if role in ("bob", "both"):
    gen_bob()

print("\n✓ Key generation complete!")
EOF
