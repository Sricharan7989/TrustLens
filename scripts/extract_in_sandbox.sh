#!/usr/bin/env bash
# Dev C. Extract zip, tar.gz, or whl INSIDE a no-network bwrap sandbox.
# Data filter (bench/tools/archive_filter.py): no symlinks, no absolute paths, no '..'.
# Never extracts on the host. Encrypted zip members try password 'infected' (Datadog convention).
# Usage: scripts/extract_in_sandbox.sh <archive> <out_dir>
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: scripts/extract_in_sandbox.sh <archive> <out_dir>" >&2
  exit 2
fi
command -v bwrap >/dev/null || { echo "bwrap missing: run scripts/check_env.sh"; exit 2; }
Z="$(realpath "$1")"
OUT="$(realpath -m "$2")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILTER="$ROOT/bench/tools/archive_filter.py"
[[ -f "$FILTER" ]] || { echo "archive filter missing: $FILTER" >&2; exit 2; }
[[ -f "$Z" ]] || { echo "archive missing: $Z" >&2; exit 2; }
base="$(basename -- "$Z")"
case "$base" in
  *$'\n'*|*'/'*|'' ) echo "refusing archive name" >&2; exit 2;;
esac
mkdir -p "$OUT"
bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
  --proc /proc --dev /dev --tmpfs /tmp \
  --ro-bind "$FILTER" /filter.py \
  --ro-bind "$Z" "/in/${base}" \
  --bind "$OUT" /out \
  --unshare-all --die-with-parent --clearenv \
  --setenv PATH /usr/bin:/bin \
  --setenv PYTHONDONTWRITEBYTECODE 1 \
  python3 /filter.py "/in/${base}" /out
