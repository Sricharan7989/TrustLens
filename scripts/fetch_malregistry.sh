#!/usr/bin/env bash
# Dev C, BACKUP malicious pool. pypi_malregistry has NO LICENSE: keep local under data/, never commit, never redistribute.
# Usage: scripts/fetch_malregistry.sh pkg1 pkg2 ...   (sparse checkout of just those package folders; never the whole 1.4 GB without a reason)
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$#" -ge 1 ] || { echo "give package folder names, e.g. ython-binance 11cent"; exit 2; }
mkdir -p data/malregistry && cd data/malregistry
[ -d mr ] || git clone --filter=blob:none --no-checkout --depth 1 https://github.com/lxyeternal/pypi_malregistry.git mr
cd mr && git sparse-checkout init --cone && git sparse-checkout set "$@" && git checkout main
