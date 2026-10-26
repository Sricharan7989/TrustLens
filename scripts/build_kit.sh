#!/usr/bin/env bash
# Zip exactly the committed files (no venv/data/reports). Needs only git. Usage: scripts/build_kit.sh [out.zip]  (commit first!)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(realpath -m "${1:-../trustlens_kit.zip}")"
rm -f "$OUT"
git archive --format=zip --prefix=trustlens/ -o "$OUT" HEAD
echo "built $OUT ($(du -h "$OUT" | cut -f1)); uncommitted changes are NOT included: $(git status --short | wc -l) pending"
