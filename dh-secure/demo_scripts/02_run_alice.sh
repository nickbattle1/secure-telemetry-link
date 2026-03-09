#!/bin/bash
# Run Alice (ground control station) to receive telemetry from aircraft

echo "Starting Alice (Ground Control Station)..."
echo ""

# Use python3 if available, otherwise fall back to python
if command -v python3 &> /dev/null; then
    python3 alice.py --host 0.0.0.0 --port 9000
else
    python alice.py --host 0.0.0.0 --port 9000
fi