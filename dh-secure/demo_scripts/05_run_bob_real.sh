#!/bin/bash
# Run Bob (aircraft flight computer) with real ADS-C telemetry data

echo "Starting Bob (Aircraft Flight Computer) with Real ADS-C Data..."
echo ""

# Check if CSV file exists
if [ ! -f "adsc_sample.csv" ]; then
    echo "ERROR: adsc_sample.csv not found"
    echo "Please run: python3 preprocess_adsc.py --input your_adsc_file.txt"
    exit 1
fi

# Run Bob with real telemetry
python3 bob.py \
    --host 192.168.0.37 \
    --port 9000 \
    --telemetry-mode real \
    --telemetry-file adsc_sample.csv \
    --duration 60