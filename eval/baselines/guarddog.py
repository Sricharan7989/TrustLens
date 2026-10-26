"""GuardDog baseline (Apache-2.0). Command verified on the toy packages (see docs/CONTRACTS.md 5)."""
from __future__ import annotations

import json
import shutil
import subprocess
import time

EXCLUDE = ["typosquatting", "potentially_compromised_email_domain", "unclaimed_maintainer_email_domain"]  # these rules need network


def run(pkg_dir: str, timeout_s: int = 180) -> dict:
    exe = shutil.which("guarddog")
    if not exe:
        return {"available": False, "flagged": None, "rules": [], "runtime_s": None, "error": "guarddog not installed"}
    cmd = [exe, "pypi", "scan", pkg_dir, "--output-format", "json"] + [x for r in EXCLUDE for x in ("-x", r)]
    t0 = time.time()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s).stdout
        data = json.loads(out)
    except Exception as e:  # noqa: BLE001
        return {"available": True, "flagged": None, "rules": [], "runtime_s": round(time.time() - t0, 2), "error": str(e)[:200]}
    rules = [r for r, v in (data.get("results") or {}).items() if v]
    return {"available": True, "flagged": bool(rules), "rules": rules, "runtime_s": round(time.time() - t0, 2), "error": None}
