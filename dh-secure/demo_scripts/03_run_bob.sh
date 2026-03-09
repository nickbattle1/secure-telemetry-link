#!/bin/bash
# Run Bob (aircraft flight computer) to transmit telemetry

echo "Starting Bob (Aircraft Flight Computer)..."
echo ""

# Connect to Alice (ground control) on laptop
python3 bob.py --host 192.168.0.37 --port 9000 --duration 60