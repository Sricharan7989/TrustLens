"""Dev B: optional static side-signals (GuardDog). Never decides a verdict. Skipped by default and when not installed."""
from __future__ import annotations

import json
import shutil
import subprocess

GD_EXCLUDES = ["typosquatting", "potentially_compromised_email_domain", "unclaimed_maintainer_email_domain"]  # these need network


def collect_static_signals(pkg_path: str, enabled: bool = False, timeout_s: int = 120) -> list[dict]:
    """Return [{source, rule, message, file, line}]. Verified command from ps1_report_comparison_and_repo_usage.md."""
    if not enabled or not shutil.which("guarddog"):
        return []
    cmd = ["guarddog", "pypi", "scan", pkg_path, "--output-format", "json"]
    for r in GD_EXCLUDES:
        cmd += ["-x", r]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout_s, text=True).stdout
        data = json.loads(out)
    except Exception:  # noqa: BLE001
        return []
    sig = []
    for rule, res in (data.get("results") or {}).items():
        for hit in (res if isinstance(res, list) else [res] if res else []):
            loc = hit.get("location", "") if isinstance(hit, dict) else ""
            f, _, ln = loc.partition(":")
            sig.append({"source": "guarddog", "rule": rule, "message": (hit.get("message") if isinstance(hit, dict) else str(hit)),
                        "file": f or None, "line": int(ln) if ln.isdigit() else None})
    return sig
