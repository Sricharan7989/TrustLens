"""PipCanary baseline (MIT). Needs bwrap + strace on PATH. NOTE: PipCanary installs with the network SHARED (it is the baseline, not our sandbox);
run it only on toy/clean packages on a throwaway machine, and never on real malware samples outside a VM.
Local-dir build can fail (missing build deps): reported as error, flagged=None. Verified only on evil_slug (flagged) in earlier tests."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def run(pkg_dir: str, timeout_s: int = 300) -> dict:
    exe = shutil.which("pipcanary")
    if not exe or not shutil.which("strace") or not shutil.which("bwrap"):
        return {"available": False, "flagged": None, "rules": [], "runtime_s": None, "error": "pipcanary, strace or bwrap missing"}
    d = Path(tempfile.mkdtemp(prefix="pc-"))
    req = d / "req.txt"
    req.write_text(str(Path(pkg_dir).resolve()) + "\n")
    t0 = time.time()
    try:
        p = subprocess.run([exe, "-r", str(req), "-d", str(Path(pkg_dir).resolve()), "-t", str(d / "trace.txt")], capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:  # noqa: BLE001
        return {"available": True, "flagged": None, "rules": [], "runtime_s": round(time.time() - t0, 2), "error": str(e)[:200]}
    out = p.stdout + p.stderr
    flagged = "Found suspicious access" in out
    err = None if (flagged or "Scanning packages" in out and "error" not in out.lower()) else out[-200:]
    return {"available": True, "flagged": flagged if err is None else None, "rules": ["credential_path_access"] if flagged else [], "runtime_s": round(time.time() - t0, 2), "error": err}
