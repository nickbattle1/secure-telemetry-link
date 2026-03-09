#!/bin/bash
# Run attacker proxy to demonstrate MITM protection

echo "Starting Attacker (MITM Proxy)..."
echo ""
echo "Instructions:"
echo "  1. Start Alice (ground control) on port 9000 (in another terminal)"
echo "  2. Run this attacker script (listens on port 9001)"
echo "  3. Run Bob (aircraft) connecting to port 9001 instead of 9000"
echo "     Example: python3 bob.py --port 9001"
echo ""
echo "The attacker will intercept and tamper with messages."
echo "The cryptographic protections should detect this and fail the handshake."
echo ""

python attacker.py --alice-port 9001 --bob-host 192.168.0.37 --bob-port 9000