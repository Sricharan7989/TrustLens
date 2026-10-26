#!/usr/bin/env bash
# Dev C. Top-PyPI list (curl -L: the old URL redirects) + download N clean controls WITHOUT running pip/setup.py.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/clean
curl -sSL https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json -o data/clean/top-pypi.json
python bench/tools/pick_clean.py --n "${1:-30}" --seed 1337 --max-kb 400
