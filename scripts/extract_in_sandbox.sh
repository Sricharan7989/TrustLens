#!/usr/bin/env bash
# Dev C. Extract a password-protected malware zip INSIDE a no-network bwrap sandbox. Never extract on the host.
# Usage: scripts/extract_in_sandbox.sh <file.zip> <out_dir>      (password 'infected' = Datadog dataset convention)
set -euo pipefail
Z="$(realpath "$1")"; OUT="$(realpath -m "$2")"; mkdir -p "$OUT"
command -v bwrap >/dev/null || { echo "bwrap missing: run scripts/check_env.sh"; exit 2; }
command -v unzip >/dev/null || { echo "unzip missing"; exit 2; }
bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin --proc /proc --dev /dev --tmpfs /tmp \
  --ro-bind "$Z" /in.zip --bind "$OUT" /out --unshare-all --die-with-parent --clearenv --setenv PATH /usr/bin:/bin \
  unzip -o -q -P infected /in.zip -d /out
# files are data only; TrustLens will execute them inside ITS sandbox, never here
ls "$OUT"
