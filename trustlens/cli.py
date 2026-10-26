"""Dev D: orchestrator. Calls A (run_package) -> B (claims, fingerprint, engine) -> D (report) ONLY through frozen contracts.

Usage: python -m trustlens scan <pkg_dir> [--runner auto|fixture|live] [--profiles dev,ci] [--out DIR] [--format text|json|html] [--offline]
       python -m trustlens check-env
Exit codes: 0 PASS, 10 REVIEW (SUSPICIOUS or INCONCLUSIVE), 20 BLOCK, 2 usage/runtime error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from trustlens.contracts import validate


def scan(pkg_path: str, out_dir: str, *, runner: str = "auto", profiles=("dev", "ci"), offline: bool = True, static: bool = False, check_contracts: bool = True) -> dict:
    """Programmatic API used by eval/ and tests: returns {verdict, fingerprint, claims, out_dir}."""
    from trustlens.claims import extract_claims, read_package_info
    from trustlens.engine import evaluate
    from trustlens.fingerprint import build_fingerprint, collect_static_signals
    from trustlens.report import render_html, render_json
    from trustlens.sandbox import run_package

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    claims = extract_claims(pkg_path)
    run = run_package(pkg_path, str(out), profiles=profiles, offline=offline, runner=runner)
    fp = build_fingerprint(run["raw_events_path"], run["run_meta"], read_package_info(pkg_path), collect_static_signals(pkg_path, enabled=static and not offline))
    verdict = evaluate(fp, claims)
    if check_contracts:
        for kind, obj in (("claims", claims), ("run_meta", run["run_meta"]), ("fingerprint", fp), ("verdict", verdict)):
            validate(kind, obj)
    (out / "claims.json").write_text(json.dumps(claims, indent=1))
    (out / "fingerprint.json").write_text(json.dumps(fp, indent=1))
    (out / "verdict.json").write_text(json.dumps(verdict, indent=1))
    (out / "report.html").write_text(render_html(verdict, fp, claims))
    (out / "report.json").write_text(render_json(verdict, fp, claims))
    return {"verdict": verdict, "fingerprint": fp, "claims": claims, "out_dir": str(out)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="trustlens")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.add_argument("--runner", default="auto", choices=["auto", "fixture", "live"])
    s.add_argument("--profiles", default="dev,ci")
    s.add_argument("--out", default=None)
    s.add_argument("--format", default="text", choices=["text", "json", "html"])
    s.add_argument("--offline", action="store_true", default=True, help="always on: no external services (kept for explicitness)")
    s.add_argument("--static", action="store_true", help="add GuardDog static signals if installed (not with --offline)")
    sub.add_parser("check-env")
    a = ap.parse_args(argv)
    if a.cmd == "check-env":
        from trustlens.sandbox import check_env

        res = check_env()
        print(json.dumps(res, indent=1))
        return 0 if res["bwrap_ok"] else 2
    from trustlens.report import render_html, render_text

    out = a.out or f"reports/{Path(a.path).resolve().name}"
    try:
        r = scan(a.path, out, runner=a.runner, profiles=tuple(a.profiles.split(",")), offline=a.offline, static=a.static)
    except Exception as e:  # noqa: BLE001
        print(f"trustlens: error: {e}", file=sys.stderr)
        return 2
    v = r["verdict"]
    print(render_html(v, r["fingerprint"], r["claims"]) if a.format == "html" else json.dumps(v, indent=1) if a.format == "json" else render_text(v, color=sys.stdout.isatty()))
    print(f"  report: {out}/report.html", file=sys.stderr)
    return {"PASS": 0, "REVIEW": 10, "BLOCK": 20}[v["action"]]


if __name__ == "__main__":
    raise SystemExit(main())
