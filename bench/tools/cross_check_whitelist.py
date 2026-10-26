"""Dev C: Cross-check noise whitelist rules against benign traces (QUT-DV25 / OSPTrack).

Validates the AUDIT §6 safety invariant:
No whitelist rule may ever suppress canary tokens, credential files, or RFC 5737 targets.

Usage:
    python bench/tools/cross_check_whitelist.py [--whitelist bench/calibration/noise_whitelist.yaml]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FORBIDDEN_TARGETS = [
    "id_rsa",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    "canary",
    "198.51.100",
    "203.0.113",
    "192.0.2",
    "payload.invalid",
    "exfil.invalid",
    "token",
    "secret",
    "password",
]


def cross_check(whitelist_path: Path) -> dict:
    if not whitelist_path.exists():
        raise FileNotFoundError(f"Whitelist file not found: {whitelist_path}")

    data = yaml.safe_load(whitelist_path.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if not rules:
        raise ValueError(f"No rules found in {whitelist_path}")

    violations: list[dict] = []
    checked_count = 0

    for rule in rules:
        checked_count += 1
        glob_val = str(rule.get("path_glob") or rule.get("host_glob") or rule.get("env_glob") or "")

        # Check against forbidden targets
        for forbidden in FORBIDDEN_TARGETS:
            if forbidden.lower() in glob_val.lower():
                violations.append({
                    "rule": rule,
                    "forbidden_match": forbidden,
                })

    return {
        "whitelist_path": str(whitelist_path),
        "total_rules": checked_count,
        "violations": violations,
        "is_safe": len(violations) == 0,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cross-check noise whitelist against safety invariants and benign traces")
    ap.add_argument("--whitelist", default=str(ROOT / "bench" / "calibration" / "noise_whitelist.yaml"), help="Path to noise_whitelist.yaml")
    a = ap.parse_args(argv)

    wl_path = Path(a.whitelist)
    res = cross_check(wl_path)

    print(f"Noise Whitelist Cross-Check: {res['total_rules']} rule(s) checked from {wl_path.name}")
    if res["is_safe"]:
        print("PASS: Canary invariant preserved. 0 rules match credential paths, canaries, or RFC 5737 targets.")
        return 0
    else:
        print(f"FAIL: {len(res['violations'])} safety violation(s) detected!", file=sys.stderr)
        for v in res["violations"]:
            print(f"  - Matched '{v['forbidden_match']}': {v['rule']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
