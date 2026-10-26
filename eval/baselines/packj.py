"""Packj baseline wrapper (AGPL-3.0 CLI comparison only).

CRITICAL LICENSING NOTE:
Packj is licensed under AGPL-3.0. In strict accordance with repo licensing constraints:
- NO Packj source code is included or copied into this repository.
- NO Packj modules or libraries are imported into Python.
- Execution is strictly optional and invoked via CLI subprocess only if `packj` is on PATH.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path


def run(pkg_dir: str | Path, timeout_s: int = 180) -> dict:
    """Run Packj CLI against a package directory (CLI subprocess only).

    Returns:
        dict with keys:
          - available: bool (False if packj executable is not on PATH)
          - flagged: bool | None (None if unavailable or unhandled error)
          - rules: list[str] (names of triggered detection rules/attributes)
          - runtime_s: float | None
          - error: str | None
    """
    exe = shutil.which("packj")
    if not exe:
        return {
            "available": False,
            "flagged": None,
            "rules": [],
            "runtime_s": None,
            "error": "packj not installed",
        }

    pkg_path = str(Path(pkg_dir).resolve())
    cmd = [exe, "audit", pkg_path, "--output-format", "json"]

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        out = proc.stdout.strip()
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

    rules: list[str] = []
    # Packj reports attributes/risks under "risks", "alerts", or "attributes"
    for key in ("risks", "alerts", "attributes", "findings"):
        items = data.get(key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and "name" in it:
                    rules.append(str(it["name"]))
                elif isinstance(it, str):
                    rules.append(it)
        elif isinstance(items, dict):
            for k, v in items.items():
                if v:
                    rules.append(k)

    runtime_s = round(time.time() - t0, 2)
    return {
        "available": True,
        "flagged": bool(rules),
        "rules": sorted(set(rules)),
        "runtime_s": runtime_s,
        "error": None,
    }
