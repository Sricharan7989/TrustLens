"""Dev D: orchestrator. Calls A (run_package) -> B (claims, fingerprint, engine) -> D (report) ONLY through frozen contracts.

Usage: python -m trustlens scan <pkg_path|archive|requirements.txt> [--runner auto|fixture|live] [--profiles dev,ci] [--out DIR] [--format text|json|html] [--offline]
       python -m trustlens check-env
Exit codes: 0 PASS, 10 REVIEW (SUSPICIOUS or INCONCLUSIVE), 20 BLOCK, 2 usage/runtime error.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Sequence

from trustlens.contracts import validate

ARCHIVE_EXTENSIONS = (".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    try:
        base_dir.resolve().relative_to(base_dir.resolve())
        target_path.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def _find_package_root(extracted_dir: Path) -> Path:
    """Find the root directory of a Python package within extracted content."""
    if (extracted_dir / "setup.py").is_file() or (extracted_dir / "pyproject.toml").is_file():
        return extracted_dir

    subdirs = [p for p in extracted_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
    if len(subdirs) == 1:
        sd = subdirs[0]
        if (sd / "setup.py").is_file() or (sd / "pyproject.toml").is_file():
            for item in list(sd.iterdir()):
                shutil.move(str(item), str(extracted_dir / item.name))
            sd.rmdir()
            return extracted_dir
        return sd

    for sd in subdirs:
        if (sd / "setup.py").is_file() or (sd / "pyproject.toml").is_file():
            return sd

    return extracted_dir


def _extract_archive_safely(archive_path: Path, dest_dir: Path) -> Path:
    """Extract a wheel or tarball/zip safely without execution, preventing path traversal."""
    dest_dir = dest_dir.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    name_lower = archive_path.name.lower()

    if name_lower.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.infolist():
                fname = member.filename
                if fname.startswith("/") or fname.startswith("\\") or ".." in Path(fname).parts:
                    raise ValueError(f"malicious path traversal in archive: {fname}")
                target = (dest_dir / fname).resolve()
                if not _is_safe_path(dest_dir, target):
                    raise ValueError(f"path escapes extraction directory: {fname}")
            zf.extractall(dest_dir)
        return _find_package_root(dest_dir)

    if any(name_lower.endswith(ext) for ext in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        with tarfile.open(archive_path, "r:*") as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest_dir, filter="data")
            else:
                for member in tf.getmembers():
                    if member.name.startswith("/") or member.name.startswith("\\") or ".." in Path(member.name).parts:
                        raise ValueError(f"malicious path traversal in archive: {member.name}")
                    target = (dest_dir / member.name).resolve()
                    if not _is_safe_path(dest_dir, target):
                        raise ValueError(f"path escapes extraction directory: {member.name}")
                tf.extractall(dest_dir)
        return _find_package_root(dest_dir)

    raise ValueError(f"unsupported archive format: {archive_path.name}")


def _is_valid_package_dir(path: Path) -> bool:
    """Check if directory has package files."""
    if not path.is_dir():
        return False
    if (path / "setup.py").is_file() or (path / "pyproject.toml").is_file() or (path / "setup.cfg").is_file():
        return True
    return any(path.glob("*.py")) or any(path.glob("*/*.py"))


def scan(
    pkg_path: str,
    out_dir: str,
    *,
    runner: str = "auto",
    profiles: Sequence[str] = ("dev", "ci"),
    offline: bool = True,
    static: bool = False,
    check_contracts: bool = True,
) -> dict:
    """Programmatic API used by eval/ and tests: returns {verdict, fingerprint, claims, out_dir}."""
    from trustlens.claims import extract_claims, read_package_info
    from trustlens.engine import evaluate
    from trustlens.fingerprint import build_fingerprint, collect_static_signals
    from trustlens.report import render_html, render_json
    from trustlens.sandbox import run_package

    p = Path(pkg_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"target path does not exist: {pkg_path}")

    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    scan_target = p
    temp_dir = None
    if p.is_file() and any(p.name.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS):
        temp_dir = tempfile.TemporaryDirectory(prefix="trustlens_archive_")
        # Extract to a subdirectory named after the base package name so fixture runner / package detectors resolve properly
        base_pkg_name = p.stem.split("-")[0].split(".tar")[0]
        extract_dest = Path(temp_dir.name) / base_pkg_name
        scan_target = _extract_archive_safely(p, extract_dest)

    try:
        claims = extract_claims(str(scan_target))
        run = run_package(str(scan_target), str(out), profiles=tuple(profiles), offline=offline, runner=runner)
        fp = build_fingerprint(
            run["raw_events_path"],
            run["run_meta"],
            read_package_info(str(scan_target)),
            collect_static_signals(str(scan_target), enabled=static and not offline),
        )
        verdict = evaluate(fp, claims)
        if check_contracts:
            for kind, obj in (("claims", claims), ("run_meta", run["run_meta"]), ("fingerprint", fp), ("verdict", verdict)):
                validate(kind, obj)

        (out / "claims.json").write_text(json.dumps(claims, indent=1), encoding="utf-8")
        (out / "fingerprint.json").write_text(json.dumps(fp, indent=1), encoding="utf-8")
        (out / "verdict.json").write_text(json.dumps(verdict, indent=1), encoding="utf-8")
        (out / "report.html").write_text(render_html(verdict, fp, claims), encoding="utf-8")
        (out / "report.json").write_text(render_json(verdict, fp, claims), encoding="utf-8")
        return {"verdict": verdict, "fingerprint": fp, "claims": claims, "out_dir": str(out), "run_meta": run["run_meta"]}
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def _get_runner_display(runner_req: str) -> str:
    from trustlens.sandbox.env_check import check_env

    if runner_req == "auto":
        is_live = bool(check_env().get("bwrap_ok"))
        return "LIVE (bwrap)" if is_live else "RECORDED FIXTURE (stub)"
    if runner_req == "live":
        return "LIVE (bwrap)"
    if runner_req == "fixture":
        return "RECORDED FIXTURE (stub)"
    return runner_req.upper()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="trustlens",
        description="TrustLens AI: Deterministic, rule-based behavioral provenance for Python dependencies.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a package directory, wheel/sdist, or requirements.txt")
    s.add_argument("path", help="Path to package directory, archive (.whl/.tar.gz/.zip), or requirements.txt")
    s.add_argument("--runner", default="auto", choices=["auto", "fixture", "live", "docker"], help="Runner mode")
    s.add_argument("--profiles", default="dev,ci", help="Comma-separated environments (e.g. dev,ci)")
    s.add_argument("--out", default=None, help="Output directory for reports and artifacts")
    s.add_argument("--format", default="text", choices=["text", "json", "html"], help="Output format")
    s.add_argument("--offline", action="store_true", default=True, help="Network off (default: True)")
    s.add_argument("--static", action="store_true", help="Add GuardDog static signals if installed (not with --offline)")

    sub.add_parser("check-env", help="Check host sandbox capabilities (bwrap, namespaces, docker)")

    d = sub.add_parser("demo-all", help="Scan every package in bench/labels.yaml and print verification table")
    d.add_argument("--runner", default="fixture", choices=["auto", "fixture", "live", "docker"], help="Runner mode")
    d.add_argument("--labels", default="bench/labels.yaml", help="Path to ground truth labels YAML")

    a = ap.parse_args(argv)

    if a.cmd == "demo-all":
        import yaml
        from trustlens.contracts import ROOT

        labels_file = Path(a.labels)
        if not labels_file.is_absolute():
            labels_file = ROOT / labels_file
        if not labels_file.exists():
            print(f"trustlens: error: labels file not found: '{a.labels}'", file=sys.stderr)
            return 2

        data = yaml.safe_load(labels_file.read_text(encoding="utf-8"))
        packages = data.get("packages", [])

        exit_code_map = {"PASS": 0, "REVIEW": 10, "BLOCK": 20}
        headers = ("Package", "Label", "Observed Verdict", "Exit Code", "Expected Verdict", "OK?")
        rows = []
        all_ok = True

        print(f"[*] Running TrustLens Demo-All across {len(packages)} bench packages (runner: {a.runner})...\n", file=sys.stderr)
        for pkg_entry in packages:
            pid = pkg_entry["id"]
            label = pkg_entry.get("label", "unknown")
            expected_verdict = pkg_entry.get("expected_verdict", "UNKNOWN")
            pkg_rel_path = pkg_entry["path"]
            pkg_full_path = ROOT / pkg_rel_path
            out_dir = Path("reports/demo-all") / pid

            try:
                res = scan(str(pkg_full_path), str(out_dir), runner=a.runner, offline=True)
                v = res["verdict"]
                obs_verdict = v["verdict"]
                ec = exit_code_map.get(v["action"], 2)
                ok = "OK" if obs_verdict == expected_verdict else "MISMATCH"
                if ok != "OK":
                    all_ok = False
                rows.append((pid, label, obs_verdict, str(ec), expected_verdict, ok))
            except Exception as ex:  # noqa: BLE001
                rows.append((pid, label, "ERROR", "2", expected_verdict, f"ERR: {ex}"))
                all_ok = False

        # Print formatted table
        col_widths = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
        format_row = lambda cols: "  ".join(cols[i].ljust(col_widths[i]) for i in range(len(cols)))
        sep = "  ".join("-" * w for w in col_widths)

        print(format_row(headers))
        print(sep)
        for row in rows:
            print(format_row(row))
        print(sep)

        if all_ok:
            print(f"\n[+] All {len(packages)} packages verified successfully against expected verdicts.")
            return 0
        else:
            print(f"\n[-] One or more packages failed verification.", file=sys.stderr)
            return 10

    if a.cmd == "check-env":
        from trustlens.sandbox import check_env

        res = check_env()
        print(json.dumps(res, indent=1))
        if not res.get("bwrap_ok"):
            print("Note: bwrap is not available. Live runner will not be able to execute; use '--runner fixture'.", file=sys.stderr)
            return 2
        return 0

    target_path = Path(a.path)
    if not target_path.exists():
        print(f"trustlens: error: path does not exist: '{a.path}'", file=sys.stderr)
        return 2

    # Check for live runner compatibility
    if a.runner == "live":
        from trustlens.sandbox.env_check import check_env

        env = check_env()
        if not env.get("bwrap_ok"):
            print("trustlens: error: live runner requires bwrap. Run 'python -m trustlens check-env' to diagnose or use '--runner fixture'.", file=sys.stderr)
            return 2

    runner_mode_str = _get_runner_display(a.runner)
    print(f"[*] TrustLens Runner: {runner_mode_str}", file=sys.stderr)

    # Handle requirements.txt
    if target_path.is_file() and target_path.name.endswith(".txt"):
        lines = [line.strip() for line in target_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]
        local_paths = []
        for line in lines:
            line_clean = line.removeprefix("-e ").strip()
            cand = (target_path.parent / line_clean).resolve()
            if cand.exists():
                local_paths.append(cand)
            elif Path(line_clean).exists():
                local_paths.append(Path(line_clean).resolve())

        if not local_paths:
            print(f"trustlens: error: no local packages found in requirements file '{a.path}'. In --offline mode, requirements must point to local package paths or wheels.", file=sys.stderr)
            return 2

        worst_action = "PASS"
        exit_code_map = {"PASS": 0, "REVIEW": 10, "BLOCK": 20}
        priority_map = {"BLOCK": 3, "REVIEW": 2, "PASS": 1}

        for lp in local_paths:
            sub_out = Path(a.out or f"reports/{lp.name}")
            print(f"\n[*] Scanning dependency from requirements: {lp.name} -> {sub_out}", file=sys.stderr)
            try:
                r = scan(str(lp), str(sub_out), runner=a.runner, profiles=tuple(a.profiles.split(",")), offline=a.offline, static=a.static)
            except Exception as e:  # noqa: BLE001
                print(f"trustlens: error scanning '{lp}': {e}", file=sys.stderr)
                return 2
            v = r["verdict"]
            from trustlens.report import render_html, render_text
            print(render_html(v, r["fingerprint"], r["claims"]) if a.format == "html" else json.dumps(v, indent=1) if a.format == "json" else render_text(v, color=sys.stdout.isatty()))
            if priority_map[v["action"]] > priority_map[worst_action]:
                worst_action = v["action"]

        return exit_code_map[worst_action]

    # Validate package directory or archive
    is_archive = any(target_path.name.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS)
    if not is_archive and not _is_valid_package_dir(target_path):
        print(f"trustlens: error: '{a.path}' is not a valid Python package (missing setup.py, pyproject.toml, or Python files)", file=sys.stderr)
        return 2

    out = a.out or f"reports/{target_path.resolve().name}"
    try:
        r = scan(str(target_path), out, runner=a.runner, profiles=tuple(a.profiles.split(",")), offline=a.offline, static=a.static)
    except Exception as e:  # noqa: BLE001
        print(f"trustlens: error: {e}", file=sys.stderr)
        return 2

    v = r["verdict"]
    from trustlens.report import render_html, render_text

    print(render_html(v, r["fingerprint"], r["claims"]) if a.format == "html" else json.dumps(v, indent=1) if a.format == "json" else render_text(v, color=sys.stdout.isatty()))
    print(f"  report: {out}/report.html", file=sys.stderr)
    return {"PASS": 0, "REVIEW": 10, "BLOCK": 20}[v["action"]]


if __name__ == "__main__":
    raise SystemExit(main())
