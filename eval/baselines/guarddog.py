"""GuardDog 3.2.0 baseline wrapper (Apache-2.0).

CLI command verified against local package directories.
For offline evaluation, the 3 network-dependent rules are explicitly excluded:
1. typosquatting: requires querying PyPI registry API for popular package names.
2. potentially_compromised_email_domain: requires WHOIS / DNS domain age lookups.
3. unclaimed_maintainer_email_domain: requires DNS MX / domain registration lookups.

All remaining static rules (AST, Semgrep, YARA) run fully offline on the local directory.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Network-dependent rules excluded for offline reproducibility
EXCLUDE = [
    "typosquatting",
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
]


def run(pkg_dir: str | Path, timeout_s: int = 180) -> dict:
    """Run GuardDog 3.2.0 against a package directory.

    Returns:
        dict with keys:
          - available: bool (False if guarddog binary not found on PATH)
          - flagged: bool | None (None if unavailable or unhandled error)
          - rules: list[str] (names of triggered detection rules)
          - runtime_s: float | None
          - error: str | None
    """
    exe = None
    bin_dir = Path(sys.executable).parent
    for cand in (bin_dir / "guarddog", bin_dir / "guarddog.exe"):
        if cand.is_file():
            exe = str(cand)
            break
    if not exe:
        root = Path(__file__).resolve().parents[2]
        for cand in (root / ".venv" / "bin" / "guarddog", root / ".venv" / "Scripts" / "guarddog.exe", root / ".venv" / "Scripts" / "guarddog"):
            if cand.is_file():
                exe = str(cand)
                break
    if not exe:
        exe = shutil.which("guarddog")
    if not exe:
        return {
            "available": False,
            "flagged": None,
            "rules": [],
            "runtime_s": None,
            "error": "guarddog not installed",
        }

    pkg_path = str(Path(pkg_dir).resolve())
    cmd = [exe, "pypi", "scan", pkg_path, "--output-format", "json"]
    for r in EXCLUDE:
        cmd.extend(["-x", r])

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        out = proc.stdout.strip()
        # Find start and end of JSON payload if there are logging prefixes
        start_idx = out.find("{")
        end_idx = out.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
            data = json.loads(out[start_idx : end_idx + 1])
        elif out:
            data = json.loads(out)
        else:
            data = {}
    except Exception as e:  # noqa: BLE001
        return {
            "available": True,
            "flagged": None,
            "rules": [],
            "runtime_s": round(time.time() - t0, 2),
            "error": str(e)[:200],
        }

    results = data.get("results")
    rules: list[str] = []
    if isinstance(results, dict):
        rules = [r for r, v in results.items() if v]
    elif isinstance(results, list):
        for item in results:
            if isinstance(item, dict) and item.get("rule"):
                rules.append(str(item["rule"]))
            elif isinstance(item, str):
                rules.append(item)

    runtime_s = round(time.time() - t0, 2)
    return {
        "available": True,
        "flagged": bool(rules),
        "rules": sorted(set(rules)),
        "runtime_s": runtime_s,
        "error": None,
    }
