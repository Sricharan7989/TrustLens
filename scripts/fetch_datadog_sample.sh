#!/usr/bin/env bash
# Dev C. Seeded Datadog PyPI sample (blobless sparse clone; NEVER the codeload zip of the whole repo: npm alone is >27 GB).
# Usage: scripts/fetch_datadog_sample.sh [N=150] [--dry-run]
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-150}"; shift || true
python bench/tools/sample_datadog.py --n "$N" --seed 1337 "$@"
