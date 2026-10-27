#!/usr/bin/env bash
# Dev C: OSPtrack dataset fetch (CC-BY-4.0).
# - data_metrics.csv (2.7 MB): attack type / trigger / obfuscation metadata for 20,248 packages (6,683 PyPI + 13,565 npm).
# - label_data_v2.csv (1.76 GB, md5 1d3aeaa9e1b338603c2f4ce8e6f5d68c): dynamic execution traces.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/osptrack

MODE="${1:-all}"

echo "Fetching OSPTrack attack and trigger metrics (data_metrics.csv)..."
curl -sSL -o data/osptrack/data_metrics.csv https://raw.githubusercontent.com/Wapiti08/OSPTrack/main/stas/data_metrics.csv
echo "data_metrics.csv downloaded successfully ($(wc -l < data/osptrack/data_metrics.csv) lines)."

if [[ "$MODE" == "--metrics-only" ]]; then
    echo "Metrics-only mode requested; skipping 1.76 GB trace download."
    exit 0
fi

if [[ "$MODE" == "--check-only" ]]; then
    echo "Checking Zenodo URL availability..."
    curl -I -sSL --fail "https://zenodo.org/api/records/21853840/files/label_data_v2.csv/content" | head -n 10
    exit 0
fi

echo "Fetching OSPTrack label_data_v2.csv (1.76 GB)..."
curl -L --fail -C - -o data/osptrack/label_data_v2.csv "https://zenodo.org/api/records/21853840/files/label_data_v2.csv/content"

echo "Verifying MD5 checksum..."
echo "1d3aeaa9e1b338603c2f4ce8e6f5d68c  data/osptrack/label_data_v2.csv" | md5sum -c -
echo "OSPTrack fetch and MD5 verification complete."
