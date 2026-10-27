#!/usr/bin/env bash
# Dev C. Extract a malware archive (zip, tar.gz, tgz, tar, whl) INSIDE a no-network bwrap sandbox.
# Never extract on the host. Data filter prevents path traversal and symlink escapes.
# Usage: scripts/extract_in_sandbox.sh <archive_file> <out_dir>
set -euo pipefail
ARCHIVE="$(realpath "$1")"; OUT="$(realpath -m "$2")"; mkdir -p "$OUT"
command -v bwrap >/dev/null || { echo "bwrap missing: run scripts/check_env.sh" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 2; }

bwrap --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
  --ro-bind /etc /etc --proc /proc --dev /dev --tmpfs /tmp \
  --ro-bind "$ARCHIVE" /in_archive --bind "$OUT" /out \
  --unshare-all --die-with-parent --clearenv --setenv PATH /usr/bin:/bin \
  python3 -c '
import os, sys, tarfile, zipfile
from pathlib import Path

archive_path = Path("/in_archive")
out_dir = Path("/out").resolve()

name_lower = sys.argv[1].lower() if len(sys.argv) > 1 else archive_path.name.lower()

def safe_rel_path(p_str):
    clean = p_str.replace("\\", "/").strip()
    parts = [part for part in clean.split("/") if part and part != "."]
    if any(part == ".." for part in parts) or clean.startswith("/"):
        return None
    dest = (out_dir / Path(*parts)).resolve()
    if not str(dest).startswith(str(out_dir)):
        return None
    return dest

if name_lower.endswith((".tar.gz", ".tgz", ".tar")):
    with tarfile.open(archive_path, "r:*") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(out_dir, filter="data")
        else:
            for member in tar.getmembers():
                dest = safe_rel_path(member.name)
                if dest is None:
                    continue
                if member.islnk() or member.issym():
                    target = member.linkname
                    if target.startswith("/") or ".." in target:
                        continue
                tar.extract(member, out_dir)
elif name_lower.endswith((".zip", ".whl")):
    with zipfile.ZipFile(archive_path) as zf:
        pwd = b"infected"
        for member in zf.infolist():
            dest = safe_rel_path(member.filename)
            if dest is None:
                continue
            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    data = zf.read(member, pwd=pwd)
                except RuntimeError:
                    data = zf.read(member)
                dest.write_bytes(data)
else:
    sys.exit(1)
' "$ARCHIVE"

ls "$OUT"

