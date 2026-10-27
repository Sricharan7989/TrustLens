#!/usr/bin/env python3
"""Validate every example/fixture JSON against schemas/*.json, then run the pipeline on all fixtures and validate its outputs.
Exit 1 on any violation. Part of scripts/audit.sh and `make test`."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml  # noqa: E402

from trustlens.contracts import EXAMPLES, ContractError, iter_jsonl, validate  # noqa: E402

errors: list[str] = []


def check(kind: str, obj, label: str) -> None:
    try:
        validate(kind, obj)
    except ContractError as e:
        errors.append(f"{label}: {e}")


def main() -> int:
    n = 0
    for d in sorted(p for p in EXAMPLES.iterdir() if p.is_dir()):
        if (d / "raw_events.jsonl").exists():
            for i, ev in enumerate(iter_jsonl(d / "raw_events.jsonl")):
                check("raw_event", ev, f"{d.name}/raw_events.jsonl:{i + 1}")
            n += 1
        for fn, kind in (("run_meta.json", "run_meta"), ("claims.json", "claims"), ("fingerprint.json", "fingerprint"), ("verdict.json", "verdict")):
            if (d / fn).exists():
                check(kind, json.loads((d / fn).read_text()), f"{d.name}/{fn}")
                n += 1
    lab = ROOT / "bench" / "labels.yaml"
    if lab.exists():
        labels = yaml.safe_load(lab.read_text())
        check("bench_labels", labels, "bench/labels.yaml")
        for p in labels["packages"]:
            if not (ROOT / p["path"]).exists():
                errors.append(f"bench/labels.yaml: path missing {p['path']}")
    res = ROOT / "reports" / "eval" / "results.json"
    if res.exists():
        check("eval_results", json.loads(res.read_text()), "reports/eval/results.json")
    # pipeline conformance: run all labelled packages through the real modules with fixtures
    import tempfile

    from trustlens.cli import scan

    known: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        for p in (yaml.safe_load(lab.read_text())["packages"] if lab.exists() else []):
            if (EXAMPLES / Path(p["path"]).name).exists():
                try:
                    r = scan(str(ROOT / p["path"]), f"{td}/{p['id']}", runner="fixture", check_contracts=True)
                    exp = p.get("expected_verdict")
                    if exp and r["verdict"]["verdict"] != exp:
                        msg = f"{p['id']}: expected {exp}, got {r['verdict']['verdict']}"
                        if p.get("known_issue"):
                            # Label stays the ground truth; the gap is tracked, printed and still counted by the eval.
                            known.append(f"{msg} ({p['known_issue']})")
                        else:
                            errors.append(msg)
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{p['id']}: pipeline error {e}")
    print(f"audit_contracts: {n} example files checked, {len(errors)} problem(s), {len(known)} known issue(s)")
    for k in known:
        print("  KNOWN", k)
    for e in errors:
        print("  FAIL", e)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
