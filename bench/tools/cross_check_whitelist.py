"""Dev C: Cross-check noise whitelist rules against benign traces (QUT-DV25 / OSPTrack).

Validates the AUDIT §6 safety invariant:
No whitelist rule may ever suppress canary tokens, credential files, or RFC 5737 targets.

Usage:
    python bench/tools/cross_check_whitelist.py [--whitelist bench/calibration/noise_whitelist.yaml]
"""
from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustlens.fingerprint.normalize import SECRET_ENV  # noqa: E402

# Strings a too-broad glob would also match. Exact hosts and env names must not.
ADVERSARIAL_PROBES = [
    "127.0.0.1.evil.com",
    "127.0.0.10",
    "localhost.evil.com",
    "TEST_AWS_SECRET_ACCESS_KEY",
    "TEST_TOKEN",
]

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


def strings_matched_by(glob_val: str) -> list[str]:
    """Concrete strings this fnmatch glob matches, including adversarial probes.

    The check uses the same ``fnmatch`` call as the normalizer, not a substring
    search of the glob text.
    """
    seeds = [glob_val]
    if any(ch in glob_val for ch in "*?["):
        seeds.append(glob_val.replace("*", ""))
        seeds.append(glob_val.replace("*", "X"))
        seeds.append(glob_val.replace("*", ".evil.com"))
        seeds.append(glob_val.replace("*", "evil"))
    catalog = seeds + ADVERSARIAL_PROBES + FORBIDDEN_TARGETS
    matched: list[str] = []
    for sample in catalog:
        if sample in matched:
            continue
        if fnmatch.fnmatch(sample, glob_val):
            matched.append(sample)
    return matched


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
        glob_key = "path_glob" if "path_glob" in rule else "host_glob" if "host_glob" in rule else "env_glob"
        glob_val = str(rule.get(glob_key) or "")
        for sample in strings_matched_by(glob_val):
            reasons: list[str] = []
            if sample in ADVERSARIAL_PROBES:
                reasons.append("adversarial")
            for forbidden in FORBIDDEN_TARGETS:
                if forbidden.lower() in sample.lower():
                    reasons.append(forbidden)
            if glob_key == "env_glob" and SECRET_ENV.search(sample):
                reasons.append("SECRET_ENV")
            if reasons:
                violations.append({
                    "rule": rule,
                    "matched_string": sample,
                    "forbidden_match": reasons[0],
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
            print(f"  - Matched '{v['matched_string']}' ({v['forbidden_match']}): {v['rule']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
