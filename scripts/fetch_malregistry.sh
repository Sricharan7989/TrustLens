#!/usr/bin/env bash
# Dev C: BACKUP malicious pool from pypi_malregistry (lxyeternal).
#
# CRITICAL LICENSING & SAFETY REMINDERS:
# 1. pypi_malregistry has NO LICENSE: keep strictly local under data/malregistry/.
# 2. NEVER commit any sample files to git; never redistribute.
# 3. NEVER execute samples on the host machine; extract only via sandbox.
# 4. Blobless sparse checkout only: never download the whole ~1.4 GB repository.
#
# Usage:
#   scripts/fetch_malregistry.sh pkg1 pkg2 ...       # sparse checkout of specific package folders
#   scripts/fetch_malregistry.sh --list [filter]     # list available package folders
#   scripts/fetch_malregistry.sh --sample 5          # sample packages reproducibly via Python helper
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_URL="https://github.com/lxyeternal/pypi_malregistry.git"
MR_DIR="data/malregistry/mr"

mkdir -p data/malregistry

# Initialize blobless shallow clone if not already present
if [ ! -d "$MR_DIR/.git" ]; then
    echo "Initializing blobless metadata clone of pypi_malregistry..."
    git clone --filter=blob:none --no-checkout --depth 1 "$REPO_URL" "$MR_DIR"
fi

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <pkg1> <pkg2> ... | --list [filter] | --sample N [--seed S]"
    exit 1
fi

ACTION="$1"

if [ "$ACTION" = "--list" ]; then
    FILTER="${2:-}"
    if [ -n "$FILTER" ]; then
        git -C "$MR_DIR" ls-tree -d --name-only HEAD | grep -i "$FILTER" || true
    else
        { git -C "$MR_DIR" ls-tree -d --name-only HEAD || true; } | head -n 50 || true
        echo "... (run with a filter to search specific packages)"
    fi
    exit 0
fi

if [ "$ACTION" = "--sample" ]; then
    shift
    python bench/tools/sample_malregistry.py --n "${1:-5}" "${@:2}"
    exit 0
fi

# Sparse checkout of requested package folders
echo "Configuring sparse-checkout for: $*"
git -C "$MR_DIR" sparse-checkout init --cone
git -C "$MR_DIR" sparse-checkout set "$@"
git -C "$MR_DIR" -c core.protectNTFS=false checkout main

echo "Sparse checkout complete for requested packages under $MR_DIR/"
echo "Reminder: pypi_malregistry has NO LICENSE: keep local, never commit."
