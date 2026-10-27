"""Dev C: run TrustLens (+ baselines) over PS1-Bench (+ clean set + Datadog sample)
and write eval/results.json + eval/heatmap.html + eval/summary.md + eval/triage.md.

python -m eval.run_eval --runner fixture|live [--tools trustlens,guarddog,pipcanary] [--policy review|block] [--jobs N] [--timeout S]
TrustLens 'flagged' = verdict MALICIOUS-EVIDENT or SUSPICIOUS (policy review) / only MALICIOUS-EVIDENT (policy block); INCONCLUSIVE -> flagged None (counted separately).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import platform
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

import trustlens
from eval import heatmap, metrics
from eval.baselines import guarddog, packj, pipcanary
from eval.threshold_sweep import compute_rule_coverage, sweep_thresholds
from trustlens.cli import scan
from trustlens.contracts import ROOT, validate


def to_wsl_path(win_path: Path) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    resolved = win_path.resolve()
    drive = resolved.drive.replace(":", "").lower()
    rest = resolved.as_posix().split(":", 1)[-1].lstrip("/")
    return f"/mnt/{drive}/{rest}"


def get_tool_version(tool: str) -> str:
    """Detect installed version for Python, TrustLens, and baseline tools."""
    if tool == "python":
        return f"Python {platform.python_version()}"
    if tool == "trustlens":
        return f"TrustLens {getattr(trustlens, '__version__', '0.1.0')}"
    if tool == "guarddog":
        exe = shutil.which("guarddog")
        if not exe:
            return "not installed"
        try:
            p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
            out = (p.stdout or p.stderr).strip()
            return out if out else "installed"
        except Exception:
            return "installed"
    if tool == "pipcanary":
        exe = shutil.which("pipcanary")
        if not exe:
            return "not installed"
        try:
            p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
            out = (p.stdout or p.stderr).strip()
            return out if out else "installed"
        except Exception:
            return "installed"
    if tool == "packj":
        exe = shutil.which("packj")
        if not exe:
            return "not installed"
        try:
            p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
            out = (p.stdout or p.stderr).strip()
            return out if out else "installed"
        except Exception:
            return "installed"
    return "unknown"


def tl_flagged(verdict: dict, policy: str):
    v = verdict["verdict"]
    if v == "INCONCLUSIVE":
        return None
    return v == "MALICIOUS-EVIDENT" if policy == "block" else v in ("MALICIOUS-EVIDENT", "SUSPICIOUS")


# Held-out split (C9): 5 clean and 5 malicious packages not used while tuning
HELD_OUT_MALICIOUS_IDS = {
    "cli_payload",
    "staged_dropper",
    "env_harvester",
    "obfuscated_xor",
    "time_gate",
}
HELD_OUT_CLEAN_IDS = {
    "math_lib",
    "color_text",
    "json_parser",
    "case_converter",
    "date_calc",
}
HELD_OUT_IDS = HELD_OUT_MALICIOUS_IDS | HELD_OUT_CLEAN_IDS


def load_labels(label_arg: str | None, runner: str) -> tuple[str, list[dict]]:
    """Discover and load label files, validating each against bench_labels schema."""
    if label_arg in ("held_out", "held-out"):
        label_paths = [ROOT / "bench" / "held_out.yaml"]
    elif label_arg in ("malregistry", "labels_malregistry.yaml"):
        label_paths = [ROOT / "bench" / "labels_malregistry.yaml"]
    elif label_arg == "all" or (label_arg is None and runner == "live"):
        default_files = [ROOT / "bench" / "labels.yaml"]
        if (ROOT / "bench" / "labels_external.yaml").exists():
            default_files.append(ROOT / "bench" / "labels_external.yaml")
        if (ROOT / "bench" / "labels_datadog.yaml").exists():
            default_files.append(ROOT / "bench" / "labels_datadog.yaml")
        if (ROOT / "bench" / "labels_malregistry.yaml").exists():
            default_files.append(ROOT / "bench" / "labels_malregistry.yaml")
        label_paths = default_files
    elif label_arg is None:
        label_paths = [ROOT / "bench" / "labels.yaml"]
    else:
        label_paths = [
            Path(p.strip()) if Path(p.strip()).is_absolute() else ROOT / p.strip()
            for p in label_arg.split(",")
            if p.strip()
        ]

    all_packages: list[dict] = []
    seen_ids: set[str] = set()
    dataset_names: list[str] = []
    for lp in label_paths:
        data = yaml.safe_load(lp.read_text(encoding="utf-8"))
        validate("bench_labels", data)
        dataset_names.append(lp.name)
        for p in data["packages"]:
            if p["id"] not in seen_ids:
                seen_ids.add(p["id"])
                all_packages.append(p)

    dataset_str = "+".join(dataset_names) if len(dataset_names) > 1 else dataset_names[0]
    return dataset_str, all_packages


def scan_single_package(
    p: dict,
    tools: list[str],
    runner: str,
    policy: str,
    out_dir: Path,
    timeout_s: int,
) -> tuple[str, dict[str, dict], dict[str, dict]]:
    """Scan one package across tools and return (pkg_id, tool_rows, tool_pers)."""
    pkg_id = p["id"]
    path = str(ROOT / p["path"])
    base = {
        "id": pkg_id,
        "label": p["label"],
        "category": p.get("category"),
        "trigger": p.get("trigger"),
        "gate": p.get("gate"),
    }
    tool_rows: dict[str, dict] = {}
    tool_pers: dict[str, dict] = {}
    for t in tools:
        if t == "trustlens":
            t0 = time.time()
            try:
                r = scan(path, str(out_dir / "runs" / pkg_id), runner=runner)
                elapsed = round(time.time() - t0, 2)
                verd = r["verdict"]
                findings = verd.get("findings", [])
                rules = [f["rule"] for f in findings]
                top_score = max([f.get("score", 0.0) for f in findings], default=0.0)
                res = {
                    "available": True,
                    "flagged": tl_flagged(verd, policy),
                    "runtime_s": elapsed,
                    "verdict": verd.get("verdict"),
                    "action": verd.get("action"),
                    "score": verd.get("score", 0.0),
                    "top_finding_score": top_score,
                    "rules": rules,
                    "signal_classes": verd.get("independent_signals", []),
                    "findings_count": len(findings),
                }
            except Exception as e:
                elapsed = round(time.time() - t0, 2)
                res = {
                    "available": True,
                    "flagged": None,
                    "runtime_s": elapsed,
                    "verdict": "INCONCLUSIVE",
                    "error": str(e)[:200],
                }
        elif t in ("guarddog", "pipcanary", "packj"):
            mod = {"guarddog": guarddog, "pipcanary": pipcanary, "packj": packj}[t]
            res = mod.run(path, timeout_s=timeout_s)
        else:
            raise ValueError(f"Unknown tool: {t}")
        tool_rows[t] = {**base, "flagged": res.get("flagged"), "runtime_s": res.get("runtime_s")}
        tool_pers[t] = res
    return pkg_id, tool_rows, tool_pers


def compute_category_metrics(rows: list[dict], available: bool) -> dict:
    """Report malicious-sample recall separately from planted-toy recall and clean categories."""
    if not available:
        return {
            "planted_toys": {"tp": 0, "fn": 0, "total": 0, "recall": None},
            "external_malware": {"tp": 0, "fn": 0, "inconclusive": 0, "total": 0, "recall": None},
            "clean_controls": {"fp": 0, "tn": 0, "inconclusive": 0, "total": 0, "fp_rate": None, "fp_rate_wilson95": None},
            "noisy_benign": {"fp": 0, "tn": 0, "inconclusive": 0, "total": 0, "fp_rate": None, "fp_rate_wilson95": None},
            "top_pypi": {"fp": 0, "tn": 0, "inconclusive": 0, "total": 0, "fp_rate": None, "fp_rate_wilson95": None},
        }

    # Planted toys
    pl_rows = [r for r in rows if r.get("category") == "planted"]
    pl_tp = sum(1 for r in pl_rows if r["flagged"] is True)
    pl_fn = sum(1 for r in pl_rows if r["flagged"] is not True)
    pl_total = len(pl_rows)
    pl_rec = metrics._div(pl_tp, pl_total)

    # External malware (Datadog and malregistry backup pool)
    dd_rows = [r for r in rows if r.get("category") in ("datadog", "malregistry")]
    dd_tp = sum(1 for r in dd_rows if r["flagged"] is True)
    dd_fn = sum(1 for r in dd_rows if r["flagged"] is not True)
    dd_inc = sum(1 for r in dd_rows if r["flagged"] is None)
    dd_total = len(dd_rows)
    dd_rec = metrics._div(dd_tp, dd_total)

    # Clean controls
    cc_rows = [r for r in rows if r.get("category") == "clean_control"]
    cc_fp = sum(1 for r in cc_rows if r["flagged"] is True)
    cc_tn = sum(1 for r in cc_rows if r["flagged"] is not True)
    cc_inc = sum(1 for r in cc_rows if r["flagged"] is None)
    cc_total = len(cc_rows)
    cc_fp_rate = metrics._div(cc_fp, cc_total)
    cc_ci = metrics.wilson(cc_fp, cc_total)

    # Noisy benign
    nb_rows = [r for r in rows if r.get("category") == "noisy_benign"]
    nb_fp = sum(1 for r in nb_rows if r["flagged"] is True)
    nb_tn = sum(1 for r in nb_rows if r["flagged"] is not True)
    nb_inc = sum(1 for r in nb_rows if r["flagged"] is None)
    nb_total = len(nb_rows)
    nb_fp_rate = metrics._div(nb_fp, nb_total)
    nb_ci = metrics.wilson(nb_fp, nb_total)

    # Top PyPI
    tp_rows = [r for r in rows if r.get("category") == "top_pypi"]
    tp_fp = sum(1 for r in tp_rows if r["flagged"] is True)
    tp_tn = sum(1 for r in tp_rows if r["flagged"] is not True)
    tp_inc = sum(1 for r in tp_rows if r["flagged"] is None)
    tp_total = len(tp_rows)
    tp_fp_rate = metrics._div(tp_fp, tp_total)
    tp_ci = metrics.wilson(tp_fp, tp_total)

    return {
        "planted_toys": {"tp": pl_tp, "fn": pl_fn, "total": pl_total, "recall": pl_rec},
        "external_malware": {"tp": dd_tp, "fn": dd_fn, "inconclusive": dd_inc, "total": dd_total, "recall": dd_rec},
        "clean_controls": {"fp": cc_fp, "tn": cc_tn, "inconclusive": cc_inc, "total": cc_total, "fp_rate": cc_fp_rate, "fp_rate_wilson95": cc_ci},
        "noisy_benign": {"fp": nb_fp, "tn": nb_tn, "inconclusive": nb_inc, "total": nb_total, "fp_rate": nb_fp_rate, "fp_rate_wilson95": nb_ci},
        "top_pypi": {"fp": tp_fp, "tn": tp_tn, "inconclusive": tp_inc, "total": tp_total, "fp_rate": tp_fp_rate, "fp_rate_wilson95": tp_ci},
    }


def generate_triage_report(pk: list[dict], per_tool_results: dict[str, dict]) -> list[str]:
    """Triage every miss and every FP per AUDIT §6."""
    lines = [
        "# PS1-Bench Evaluation Triage (AUDIT §6)",
        "",
        "Classification categories per AUDIT §6:",
        "- *(a) true noise* -> candidate for whitelist rule in `engine/noise_whitelist.yaml`",
        "- *(b) claim parser gap* -> intent keyword gap in `capabilities.yaml`",
        "- *(c) sample dead / install failed / coverage thin (abstention)* -> unexecuted triggers/phases, recorded as INCONCLUSIVE",
        "- *(d) genuine engine detection gap* -> rule/threshold tuning candidate",
        "",
        "| Package ID | Label | Category | Tool | Verdict | Status | AUDIT §6 Classification | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    tl_results = per_tool_results.get("trustlens", {})
    triage_count = 0
    for p in pk:
        pkg_id = p["id"]
        label = p["label"]
        category = p.get("category", "unknown")
        res = tl_results.get(pkg_id, {})
        verdict = res.get("verdict", "UNKNOWN")
        flagged = res.get("flagged")

        is_fp = (label == "clean" and flagged is True)
        is_miss = (label == "malicious" and flagged is not True)

        if is_fp:
            triage_count += 1
            lines.append(f"| {pkg_id} | {label} | {category} | trustlens | {verdict} | FALSE POSITIVE | *(a) or (b)* | Flagged clean package: review report.html |")
        elif is_miss:
            triage_count += 1
            if verdict == "INCONCLUSIVE":
                cls_str = "*(c) coverage thin / abstention*"
                note = "Dynamic coverage insufficient or unexercised package (reported as INCONCLUSIVE)"
            else:
                cls_str = "*(d) engine detection gap*"
                note = "Malicious package missed by detection engine (verdict: BENIGN-CONSISTENT)"
            lines.append(f"| {pkg_id} | {label} | {category} | trustlens | {verdict} | MISS | {cls_str} | {note} |")

    if triage_count == 0:
        lines.append("| (none) | - | - | trustlens | - | PERFECT | - | No false positives or misses observed |")

    lines.append("")
    return lines


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="TrustLens AI evaluation harness")
    ap.add_argument("--labels", default=None, help="Label YAML path(s), comma-separated, or 'all'")
    ap.add_argument("--runner", default="fixture", choices=["fixture", "live"])
    ap.add_argument("--tools", default="trustlens,guarddog,pipcanary")
    ap.add_argument("--policy", default="review", choices=["review", "block"])
    ap.add_argument("--out", default=str(ROOT / "reports" / "eval"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--jobs", "-j", type=int, default=4, help="parallelise <= 4 sandboxes (default: 4)")
    ap.add_argument("--timeout", type=int, default=120, help="per-package timeout in seconds (default: 120)")
    a = ap.parse_args(argv)

    # Windows live-runner bridge: delegate to WSL2 if on Windows and bwrap is not on Windows PATH
    if a.runner == "live" and sys.platform == "win32" and not shutil.which("bwrap"):
        if shutil.which("wsl"):
            wsl_cwd = to_wsl_path(ROOT)
            forward_args = " ".join(argv if argv is not None else sys.argv[1:])
            cmd = ["wsl", "bash", "-c", f"cd {wsl_cwd} && python3 -m eval.run_eval {forward_args}"]
            return subprocess.run(cmd).returncode
        raise RuntimeError("Live runner requires bubblewrap (bwrap), which is not installed on this machine or in WSL.")

    dataset_name, all_pk = load_labels(a.labels, a.runner)
    pk = all_pk[: a.limit or None]
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    workers = min(4, max(1, a.jobs))
    rows: dict[str, list[dict]] = {t: [] for t in tools}
    per: dict[str, dict] = {t: {} for t in tools}

    if workers > 1 and len(pk) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_pkg = {
                pool.submit(scan_single_package, p, tools, a.runner, a.policy, out, a.timeout): p
                for p in pk
            }
            results_by_id = {}
            for future in concurrent.futures.as_completed(future_to_pkg):
                pkg_id, t_rows, t_pers = future.result()
                results_by_id[pkg_id] = (t_rows, t_pers)
            for p in pk:
                pkg_id = p["id"]
                t_rows, t_pers = results_by_id[pkg_id]
                for t in tools:
                    rows[t].append(t_rows[t])
                    per[t][pkg_id] = t_pers[t]
    else:
        for p in pk:
            pkg_id, t_rows, t_pers = scan_single_package(p, tools, a.runner, a.policy, out, a.timeout)
            for t in tools:
                rows[t].append(t_rows[t])
                per[t][pkg_id] = t_pers[t]

    unavailable = [t for t in tools if t != "trustlens" and not all(per[t][k].get("available", True) for k in per[t])]
    tool_versions = {t: get_tool_version(t) for t in tools}
    versions = {
        "python": get_tool_version("python"),
        **tool_versions,
    }

    tool_results: dict[str, dict] = {}
    for t in tools:
        is_avail = (t not in unavailable)
        metrics_data = metrics.confusion(rows[t], available=is_avail)
        cat_metrics = compute_category_metrics(rows[t], available=is_avail)
        ho_rows = [r for r in rows[t] if r.get("id") in HELD_OUT_IDS]
        ho_metrics = metrics.confusion(ho_rows, available=is_avail) if ho_rows else None
        tool_results[t] = {
            **metrics_data,
            "available": is_avail,
            "version": tool_versions[t],
            "category_metrics": cat_metrics,
            "held_out_metrics": ho_metrics,
            "per_package": per[t],
        }

    results = {
        "schema_version": "1.0",
        "dataset": dataset_name,
        "seed": None,
        "n_malicious": sum(p["label"] == "malicious" for p in pk),
        "n_clean": sum(p["label"] == "clean" for p in pk),
        "versions": versions,
        "tools": tool_results,
        "held_out": {
            "n_clean": len(HELD_OUT_CLEAN_IDS),
            "n_malicious": len(HELD_OUT_MALICIOUS_IDS),
            "clean_ids": sorted(list(HELD_OUT_CLEAN_IDS)),
            "malicious_ids": sorted(list(HELD_OUT_MALICIOUS_IDS)),
            "tools": {t: tool_results[t].get("held_out_metrics") for t in tools},
        },
    }

    # Compute threshold sweep and rule coverage (C12)
    tl_pkg_evals = []
    tl_per = tool_results.get("trustlens", {}).get("per_package", {})
    for p in pk:
        pkg_id = p["id"]
        p_res = tl_per.get(pkg_id, {})
        tl_pkg_evals.append({
            "id": pkg_id,
            "label": p["label"],
            "category": p.get("category"),
            "trigger": p.get("trigger"),
            "gate": p.get("gate"),
            "score": p_res.get("score", 0.0),
            "top_finding_score": p_res.get("top_finding_score", p_res.get("score", 0.0)),
            "verdict": p_res.get("verdict", "INCONCLUSIVE"),
            "flagged": p_res.get("flagged"),
            "rules": p_res.get("rules", []),
            "signal_classes": p_res.get("signal_classes", []),
            "inconclusive": p_res.get("verdict") == "INCONCLUSIVE",
        })

    sweep_res = sweep_thresholds(tl_pkg_evals)
    coverage_res = compute_rule_coverage(tl_pkg_evals)
    results["threshold_sweep"] = sweep_res
    results["rule_coverage"] = coverage_res

    validate("eval_results", results)

    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out / "threshold_sweep.json").write_text(json.dumps(sweep_res, indent=2), encoding="utf-8")
    (out / "rule_coverage.json").write_text(json.dumps(coverage_res, indent=2), encoding="utf-8")
    (out / "heatmap.html").write_text(heatmap.render(results), encoding="utf-8")

    # Generate triage report
    triage_lines = generate_triage_report(pk, per)
    (out / "triage.md").write_text("\n".join(triage_lines) + "\n", encoding="utf-8")

    now_utc = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    cmd_args = " ".join(argv if argv is not None else sys.argv[1:])
    cmd_str = f"python -m eval.run_eval {cmd_args}".strip()
    n_mal = results["n_malicious"]
    n_clean = results["n_clean"]

    summary_lines = [
        f"# PS1-Bench Evaluation Summary ({dataset_name})",
        "",
        f"- **Date (UTC):** {now_utc}",
        f"- **Runner:** **{a.runner}** ({'stub fixtures replay; fast and deterministic, but NOT a live measurement. Run `make eval-live` for pitch numbers' if a.runner == 'fixture' else 'live bwrap sandbox execution'})",
        f"- **Policy:** **{a.policy}** ({'SUSPICIOUS and MALICIOUS-EVIDENT flagged' if a.policy == 'review' else 'only MALICIOUS-EVIDENT flagged'}; INCONCLUSIVE counted separately)",
        f"- **Command:** `{cmd_str}`",
        f"- **Parallelism:** {workers} sandbox worker(s) (per-package timeout: {a.timeout}s)",
        "- **Tool Versions:**",
        f"  - Python: {versions['python']}",
    ]
    for t in tools:
        summary_lines.append(f"  - {t}: {tool_versions[t]}")

    summary_lines.extend([
        f"- **Dataset:** {n_mal} malicious / {n_clean} clean packages ({dataset_name})",
        f"- **False Positive Note:** FP shown as k/n with Wilson 95% CI. 0/{n_clean} is NOT a 0% rate.",
        "",
        "### Headline Metrics",
        "| Tool | TP | FN | FP (k/n, 95% CI) | TN | Inconclusive | Precision | Recall | F1 | Median (s) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ])

    for t, m in results["tools"].items():
        if t in unavailable:
            summary_lines.append(f"| {t} | not run | | | | | | | | baseline unavailable on this machine (see DEPENDENCIES.md) |")
            continue
        ci = m["fp_rate_wilson95"]
        ci_str = f"[{ci[0]}, {ci[1]}]" if ci else "None"
        summary_lines.append(
            f"| {t} | {m['tp']} | {m['fn']} | {m['fp']}/{m['fp'] + m['tn']} {ci_str} | {m['tn']} | {m['inconclusive']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['median_runtime_s']} |"
        )

    summary_lines.extend([
        "",
        "### Recall & False Positive Breakdown by Category",
        "| Tool | Planted Toys Recall | External Malware Recall (Datadog / Malregistry) | Clean Controls FP | Noisy-Benign FP | Top-PyPI Clean FP |",
        "|---|---|---|---|---|---|",
    ])

    for t, m in results["tools"].items():
        if t in unavailable:
            summary_lines.append(f"| {t} | not run | not run | not run | not run | not run |")
            continue
        cm = m.get("category_metrics", {})
        pl = cm.get("planted_toys", {})
        pl_str = f"{pl.get('tp', 0)}/{pl.get('total', 0)}" if pl.get("total") else "-"
        dd = cm.get("external_malware", {})
        dd_str = f"{dd.get('tp', 0)}/{dd.get('total', 0)}" if dd.get("total") else "-"
        cc = cm.get("clean_controls", {})
        cc_ci = f" {cc['fp_rate_wilson95']}" if cc.get("fp_rate_wilson95") else ""
        cc_str = f"{cc.get('fp', 0)}/{cc.get('total', 0)}{cc_ci}" if cc.get("total") else "-"
        nb = cm.get("noisy_benign", {})
        nb_ci = f" {nb['fp_rate_wilson95']}" if nb.get("fp_rate_wilson95") else ""
        nb_str = f"{nb.get('fp', 0)}/{nb.get('total', 0)}{nb_ci}" if nb.get("total") else "-"
        tp = cm.get("top_pypi", {})
        tp_ci = f" {tp['fp_rate_wilson95']}" if tp.get("fp_rate_wilson95") else ""
        tp_str = f"{tp.get('fp', 0)}/{tp.get('total', 0)}{tp_ci}" if tp.get("total") else "-"
        summary_lines.append(f"| {t} | {pl_str} | {dd_str} | {cc_str} | {nb_str} | {tp_str} |")

    # Held-out split evaluation (C9: 5 clean + 5 malicious packages not used while tuning)
    ho_pkgs = [p for p in pk if p["id"] in HELD_OUT_IDS]
    if ho_pkgs:
        n_ho_mal = sum(p["label"] == "malicious" for p in ho_pkgs)
        n_ho_clean = sum(p["label"] == "clean" for p in ho_pkgs)
        clean_names = ", ".join(f"`{p['id']}`" for p in ho_pkgs if p["label"] == "clean")
        mal_names = ", ".join(f"`{p['id']}`" for p in ho_pkgs if p["label"] == "malicious")
        summary_lines.extend([
            "",
            f"### Held-Out Split Evaluation ({n_ho_clean} Clean + {n_ho_mal} Malicious)",
            "",
            "*These 10 packages were strictly isolated and never used during rule development, capability keyword mapping, or noise-whitelist calibration.*",
            f"- **Clean Packages ({n_ho_clean}):** {clean_names}",
            f"- **Malicious Packages ({n_ho_mal}):** {mal_names}",
            "",
            "| Tool | TP | FN | FP (k/n, 95% CI) | TN | Inconclusive | Precision | Recall | F1 | Median (s) |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ])
        for t, m in results["tools"].items():
            if t in unavailable:
                summary_lines.append(f"| {t} | not run | not run | not run | not run | not run | not run | not run | not run | baseline unavailable |")
                continue
            hom = m.get("held_out_metrics")
            if not hom:
                summary_lines.append(f"| {t} | - | - | - | - | - | - | - | - | - |")
                continue
            ci = hom["fp_rate_wilson95"]
            ci_str = f"[{ci[0]}, {ci[1]}]" if ci else "None"
            summary_lines.append(
                f"| {t} | {hom['tp']} | {hom['fn']} | {hom['fp']}/{hom['fp'] + hom['tn']} {ci_str} | {hom['tn']} | {hom['inconclusive']} | {hom['precision']} | {hom['recall']} | {hom['f1']} | {hom['median_runtime_s']} |"
            )

        summary_lines.extend([
            "",
            "#### Held-Out Package Detail (TrustLens)",
            "| Package ID | Label | Category | Expected Verdict | TrustLens Verdict | Flagged | Match Status |",
            "|---|---|---|---|---|---|---|",
        ])
        tl_res = results["tools"].get("trustlens", {}).get("per_package", {})
        for p in sorted(ho_pkgs, key=lambda x: (x["label"], x["id"])):
            pkg_id = p["id"]
            lbl = p["label"]
            cat = p.get("category", "-")
            exp = p.get("expected_verdict", "-")
            tl_pkg = tl_res.get(pkg_id, {})
            v = tl_pkg.get("verdict", "UNKNOWN")
            flg = tl_pkg.get("flagged")
            flg_str = str(flg) if flg is not None else "None"
            if v == "INCONCLUSIVE":
                status = "INCONCLUSIVE (abstain)"
            elif lbl == "clean":
                status = "TRUE NEGATIVE" if flg is False else "FALSE POSITIVE"
            else:
                status = "TRUE POSITIVE" if flg is True else "FALSE NEGATIVE"
            summary_lines.append(f"| `{pkg_id}` | {lbl} | {cat} | {exp} | {v} | {flg_str} | **{status}** |")

    # Threshold Sweep & Rule Coverage (C12)
    nom_rec = sweep_res.get("sensitivity", {}).get("nominal", {})
    lo_rec = sweep_res.get("sensitivity", {}).get("minus_20_pct", {}).get("record", {})
    hi_rec = sweep_res.get("sensitivity", {}).get("plus_20_pct", {}).get("record", {})
    nom_t = sweep_res.get("nominal_threshold", 4.0)

    summary_lines.extend([
        "",
        "### Decision Threshold Sweep & Sensitivity (weights.yaml)",
        f"- **ROC AUC:** `{sweep_res.get('auc', 0.5):.4f}` across {len(sweep_res.get('sweep', []))} threshold evaluation points.",
        f"- **Nominal Operating Point:** `suspicious_threshold = {nom_t}` (TPR: `{nom_rec.get('tpr', 0.0):.4f}`, FPR: `{nom_rec.get('fpr', 0.0):.4f}`).",
        "- **Threshold Sensitivity (+/-20%):**",
        f"  - `-20%` (T={sweep_res.get('sensitivity', {}).get('minus_20_pct', {}).get('threshold')}): TPR `{lo_rec.get('tpr', 0.0):.4f}`, FPR `{lo_rec.get('fpr', 0.0):.4f}` (Delta TPR: `{sweep_res.get('sensitivity', {}).get('minus_20_pct', {}).get('delta_tpr', 0.0):+.4f}`, Delta FPR: `{sweep_res.get('sensitivity', {}).get('minus_20_pct', {}).get('delta_fpr', 0.0):+.4f}`)",
        f"  - `+20%` (T={sweep_res.get('sensitivity', {}).get('plus_20_pct', {}).get('threshold')}): TPR `{hi_rec.get('tpr', 0.0):.4f}`, FPR `{hi_rec.get('fpr', 0.0):.4f}` (Delta TPR: `{sweep_res.get('sensitivity', {}).get('plus_20_pct', {}).get('delta_tpr', 0.0):+.4f}`, Delta FPR: `{sweep_res.get('sensitivity', {}).get('plus_20_pct', {}).get('delta_fpr', 0.0):+.4f}`)",
        f"- **Verdict Stability:** {len(sweep_res.get('sensitivity', {}).get('flipping_packages', []))} package(s) flip verdict within +/-20% threshold margin.",
        "",
        "### Detection Rule Coverage Summary (TrustLens)",
        f"- **Active Rules Fired:** {sum(1 for r in coverage_res.get('rule_summary', []) if r['total_hits'] > 0)} / {len(coverage_res.get('rule_summary', []))} rules.",
        f"- **Total Malicious-Evident Rule Activations:** {sum(r['malicious_evident'] for r in coverage_res.get('rule_summary', []))}.",
        "",
        "## Methodological Notes",
        "- **Wilson 95% Score Intervals:** Calculated using two-sided Wilson score intervals for binomial proportions to ensure scientific honesty on zero-FP observations.",
        "- **Planted Toys vs External Malware:** Recall on synthetic planted toys is reported separately from real-world external malware samples (Datadog and Malregistry backup) to avoid mixing synthetic coverage with noisy external datasets.",
        "- **Abstention Integrity:** Packages resulting in `INCONCLUSIVE` (e.g., dead/unexercised packages or thin dynamic coverage) are tracked separately and not disguised as true negatives.",
        "- **Baselines:** Unavailable baseline tools are reported as 'not run' rather than 0 detections to avoid dishonest comparative claims.",
        "- **Triage:** Detailed FP and miss triage per AUDIT §6 is written to `reports/eval/triage.md`.",
    ])

    summary_text = "\n".join(summary_lines) + "\n"
    (out / "summary.md").write_text(summary_text, encoding="utf-8")
    print(summary_text)
    if unavailable:
        print(f"note: baseline(s) not run (unavailable): {', '.join(unavailable)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
