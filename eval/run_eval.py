"""Dev C: run TrustLens (+ baselines) over bench/labels.yaml and write eval/results.json + eval/heatmap.html + eval/summary.md.

python -m eval.run_eval --runner fixture|live [--tools trustlens,guarddog,pipcanary] [--policy review|block] [--limit N]
TrustLens 'flagged' = verdict MALICIOUS-EVIDENT or SUSPICIOUS (policy review) / only MALICIOUS-EVIDENT (policy block); INCONCLUSIVE -> flagged None (counted separately).
"""
from __future__ import annotations

import argparse
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
from eval.baselines import guarddog, pipcanary
from trustlens.cli import scan
from trustlens.contracts import ROOT, validate


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
    return "unknown"


def tl_flagged(verdict: dict, policy: str):
    v = verdict["verdict"]
    if v == "INCONCLUSIVE":
        return None
    return v == "MALICIOUS-EVIDENT" if policy == "block" else v in ("MALICIOUS-EVIDENT", "SUSPICIOUS")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TrustLens AI evaluation harness")
    ap.add_argument("--labels", default=str(ROOT / "bench" / "labels.yaml"))
    ap.add_argument("--runner", default="fixture", choices=["fixture", "live"])
    ap.add_argument("--tools", default="trustlens,guarddog,pipcanary")
    ap.add_argument("--policy", default="review", choices=["review", "block"])
    ap.add_argument("--out", default=str(ROOT / "reports" / "eval"))
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args(argv)

    labels = yaml.safe_load(Path(a.labels).read_text(encoding="utf-8"))
    validate("bench_labels", labels)
    pk = labels["packages"][: a.limit or None]
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]

    rows: dict[str, list[dict]] = {t: [] for t in tools}
    per: dict[str, dict] = {t: {} for t in tools}
    for p in pk:
        path = str(ROOT / p["path"])
        base = {"label": p["label"], "trigger": p.get("trigger"), "gate": p.get("gate")}
        for t in tools:
            if t == "trustlens":
                t0 = time.time()
                r = scan(path, str(Path(a.out) / "runs" / p["id"]), runner=a.runner)
                res = {
                    "available": True,
                    "flagged": tl_flagged(r["verdict"], a.policy),
                    "runtime_s": round(time.time() - t0, 2),
                    "verdict": r["verdict"]["verdict"],
                }
            elif t in ("guarddog", "pipcanary"):
                mod = {"guarddog": guarddog, "pipcanary": pipcanary}[t]
                res = mod.run(path)
            else:
                raise ValueError(f"Unknown tool: {t}")
            rows[t].append({**base, "flagged": res.get("flagged"), "runtime_s": res.get("runtime_s")})
            per[t][p["id"]] = res

    unavailable = [t for t in tools if t != "trustlens" and not all(per[t][k].get("available", True) for k in per[t])]
    tool_versions = {t: get_tool_version(t) for t in tools}
    versions = {
        "python": get_tool_version("python"),
        **tool_versions,
    }

    results = {
        "schema_version": "1.0",
        "dataset": Path(a.labels).name,
        "seed": None,
        "n_malicious": sum(p["label"] == "malicious" for p in pk),
        "n_clean": sum(p["label"] == "clean" for p in pk),
        "versions": versions,
        "tools": {
            t: {
                **metrics.confusion(rows[t], available=(t not in unavailable)),
                "available": (t not in unavailable),
                "version": tool_versions[t],
                "per_package": per[t],
            }
            for t in tools
        },
    }
    validate("eval_results", results)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out / "heatmap.html").write_text(heatmap.render(results), encoding="utf-8")

    now_utc = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    cmd_args = " ".join(argv if argv is not None else sys.argv[1:])
    cmd_str = f"python -m eval.run_eval {cmd_args}".strip()
    n_mal = results["n_malicious"]
    n_clean = results["n_clean"]

    summary_lines = [
        f"# PS1-Bench Evaluation Summary ({Path(a.labels).name})",
        "",
        f"- **Date (UTC):** {now_utc}",
        f"- **Runner:** **{a.runner}** ({'stub fixtures replay; fast and deterministic, but NOT a live measurement. Run `make eval-live` for pitch numbers' if a.runner == 'fixture' else 'live bwrap sandbox execution'})",
        f"- **Policy:** **{a.policy}** ({'SUSPICIOUS and MALICIOUS-EVIDENT flagged' if a.policy == 'review' else 'only MALICIOUS-EVIDENT flagged'}; INCONCLUSIVE counted separately)",
        f"- **Command:** `{cmd_str}`",
        "- **Tool Versions:**",
        f"  - Python: {versions['python']}",
    ]
    for t in tools:
        summary_lines.append(f"  - {t}: {tool_versions[t]}")

    summary_lines.extend([
        f"- **Dataset:** {n_mal} malicious / {n_clean} clean packages ({Path(a.labels).name})",
        f"- **False Positive Note:** FP shown as k/n with Wilson 95% CI. 0/{n_clean} is NOT a 0% rate.",
        "",
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
        "## Methodological Notes",
        "- **Wilson 95% Score Intervals:** Calculated using two-sided Wilson score intervals for binomial proportions to ensure scientific honesty on zero-FP observations.",
        "- **Abstention Integrity:** Packages resulting in `INCONCLUSIVE` (e.g., unexecuted variants or insufficient dynamic coverage) are tracked separately and not disguised as true negatives.",
        "- **Baselines:** Unavailable baseline tools are reported as 'not run' rather than 0 detections to avoid dishonest comparative claims.",
    ])

    summary_text = "\n".join(summary_lines) + "\n"
    (out / "summary.md").write_text(summary_text, encoding="utf-8")
    print(summary_text)
    if unavailable:
        print(f"note: baseline(s) not run (unavailable): {', '.join(unavailable)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
