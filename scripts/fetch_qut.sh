#!/usr/bin/env bash
# Dev C, optional (calibration only). QUT-DV25: public zip, 2.14 GB, no login. Needs >= 6 GB free. Run in background.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/qut
# Check if processed CSVs already exist
if ls data/qut/QUT-DV25_*.csv >/dev/null 2>&1; then
  echo "QUT-DV25 trace tables already present in data/qut/:"
  ls -lh data/qut/QUT-DV25_*.csv
  exit 0
fi

curl -L --fail -C - -o data/qut/qut-dv25.zip "https://dataverse.harvard.edu/api/access/datafile/11542393"
unzip -o -q data/qut/qut-dv25.zip -d data/qut/   # trace tables (CSV), not executable malware
ls -la data/qut

