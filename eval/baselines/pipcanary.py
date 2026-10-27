"""PipCanary 0.1.1 baseline wrapper (MIT).

Requires `pipcanary`, `bwrap`, and `strace` on PATH.

CRITICAL SAFETY WARNING:
PipCanary runs pip install with the HOST NETWORK SHARED.
It is an external baseline, not the TrustLens isolation sandbox.
Run PipCanary ONLY on toy/clean packages on a throwaway machine.
NEVER run PipCanary on untrusted or real malware samples unless inside Docker
with `--network none` isolation.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(pkg_dir: str | Path, timeout_s: int = 300) -> dict:
    """Run PipCanary 0.1.1 against a local package directory.

    Returns:
        dict with keys:
          - available: bool (False if pipcanary, strace, or bwrap is missing)
          - flagged: bool | None (None if unavailable, unsafe, or error)
          - rules: list[str] (["credential_path_access"] if flagged)
          - runtime_s: float | None
          - error: str | None
    """
    exe = None
    bin_dir = Path(sys.executable).parent
    for cand in (bin_dir / "pipcanary", bin_dir / "pipcanary.exe"):
        if cand.is_file():
            exe = str(cand)
            break
    if not exe:
        root = Path(__file__).resolve().parents[2]
        for cand in (root / ".venv" / "bin" / "pipcanary", root / ".venv" / "Scripts" / "pipcanary.exe", root / ".venv" / "Scripts" / "pipcanary"):
            if cand.is_file():
                exe = str(cand)
                break
    if not exe:
        exe = shutil.which("pipcanary")
    if not exe or not shutil.which("strace") or not shutil.which("bwrap"):
        return {
            "available": False,
            "flagged": None,
            "rules": [],
            "runtime_s": None,
            "error": "pipcanary, strace or bwrap missing",
        }

    resolved = Path(pkg_dir).resolve()
    resolved_str = str(resolved).replace("\\", "/")

    # Malware safety invariant: PipCanary shares host network.
    # Refuse to run on real/external malware outside Docker --network none.
    is_external_malware = any(
        marker in resolved_str
        for marker in ("/data/datadog", "/data/malregistry", "/data/malware")
    )
    is_docker_isolated = (
        os.environ.get("DOCKER_NETWORK_NONE") == "1"
        or os.environ.get("ALLOW_PIPCANARY_MALWARE") == "1"
    )
    if is_external_malware and not is_docker_isolated:
        return {
            "available": True,
            "flagged": None,
            "rules": [],
            "runtime_s": 0.0,
            "error": "Safety guard: PipCanary shares host network; refused to run on real malware outside Docker --network none",
        }

    d = Path(tempfile.mkdtemp(prefix="pc-"))
    req = d / "req.txt"
    req.write_text(str(resolved) + "\n", encoding="utf-8")
    t0 = time.time()
    try:
        proc = subprocess.run(
            [exe, "-r", str(req), "-d", str(resolved), "-t", str(d / "trace.txt")],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except Exception as e:  # noqa: BLE001
        return {
            "available": True,
            "flagged": None,
            "rules": [],
            "runtime_s": round(time.time() - t0, 2),
            "error": str(e)[:200],
        }

    out = proc.stdout + proc.stderr
    flagged = "Found suspicious access" in out
    has_clean_scan = "Scanning packages" in out and "error" not in out.lower()
    err = None if (flagged or has_clean_scan) else out[-200:]

    return {
        "available": True,
        "flagged": flagged if err is None else None,
        "rules": ["credential_path_access"] if flagged else [],
        "runtime_s": round(time.time() - t0, 2),
        "error": err,
    }
