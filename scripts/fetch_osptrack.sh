#!/usr/bin/env bash
# Dev C, ONLY IF TIME. OSPtrack label_data_v2.csv (1.76 GB, md5 1d3aeaa9e1b338603c2f4ce8e6f5d68c, CC-BY-4.0): benign-trace cross-check for the whitelist.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/osptrack
curl -L --fail -C - -o data/osptrack/label_data_v2.csv "https://zenodo.org/api/records/21853840/files/label_data_v2.csv/content"
echo "1d3aeaa9e1b338603c2f4ce8e6f5d68c  data/osptrack/label_data_v2.csv" | md5sum -c -
curl -sSL -o data/osptrack/data_metrics.csv https://raw.githubusercontent.com/Wapiti08/OSPTrack/main/stas/data_metrics.csv   # attack type/trigger/obfuscation per package: use to plan planted toys
