"""Dev C: run TrustLens (+ baselines) over bench/labels.yaml and write eval/results.json + eval/heatmap.html + eval/summary.md.

python -m eval.run_eval --runner fixture|live [--tools trustlens,guarddog,pipcanary] [--policy review|block] [--limit N]
TrustLens 'flagged' = verdict MALICIOUS-EVIDENT or SUSPICIOUS (policy review) / only MALICIOUS-EVIDENT (policy block); INCONCLUSIVE -> flagged None (counted separately).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

from eval import heatmap, metrics
from eval.baselines import guarddog, pipcanary
from trustlens.cli import scan
from trustlens.contracts import ROOT, validate


def tl_flagged(verdict: dict, policy: str):
    v = verdict["verdict"]
    if v == "INCONCLUSIVE":
        return None
    return v == "MALICIOUS-EVIDENT" if policy == "block" else v in ("MALICIOUS-EVIDENT", "SUSPICIOUS")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=str(ROOT / "bench" / "labels.yaml"))
    ap.add_argument("--runner", default="fixture", choices=["fixture", "live"])
    ap.add_argument("--tools", default="trustlens,guarddog")
    ap.add_argument("--policy", default="review", choices=["review", "block"])
    ap.add_argument("--out", default=str(ROOT / "reports" / "eval"))
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args(argv)
    labels = yaml.safe_load(Path(a.labels).read_text())
    validate("bench_labels", labels)
    pk = labels["packages"][: a.limit or None]
    tools = a.tools.split(",")
    rows: dict[str, list[dict]] = {t: [] for t in tools}
    per: dict[str, dict] = {t: {} for t in tools}
    for p in pk:
        path = str(ROOT / p["path"])
        base = {"label": p["label"], "trigger": p.get("trigger"), "gate": p.get("gate")}
        for t in tools:
            if t == "trustlens":
                t0 = time.time()
                r = scan(path, str(Path(a.out) / "runs" / p["id"]), runner=a.runner)
                res = {"flagged": tl_flagged(r["verdict"], a.policy), "runtime_s": round(time.time() - t0, 2), "verdict": r["verdict"]["verdict"]}
            else:
                res = {"guarddog": guarddog, "pipcanary": pipcanary}[t].run(path)
            rows[t].append({**base, "flagged": res["flagged"], "runtime_s": res.get("runtime_s")})
            per[t][p["id"]] = res
    results = {"schema_version": "1.0", "dataset": Path(a.labels).name, "seed": None, "n_malicious": sum(p["label"] == "malicious" for p in pk), "n_clean": sum(p["label"] == "clean" for p in pk),
               "tools": {t: {**metrics.confusion(rows[t]), "per_package": per[t]} for t in tools}}
    validate("eval_results", results)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=1))
    (out / "heatmap.html").write_text(heatmap.render(results))
    unavailable = [t for t in tools if t != "trustlens" and not all(per[t][k].get("available", True) for k in per[t])]
    n_clean = results["n_clean"]
    lines = [f"# PS1-Bench eval ({Path(a.labels).name})", "",
             f"- date (UTC): {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')} - runner: **{a.runner}** - policy: {a.policy} (review = SUSPICIOUS+MALICIOUS-EVIDENT flagged; block = only MALICIOUS-EVIDENT; INCONCLUSIVE reported separately and counted as a miss/not-flagged)",
             f"- command: `python -m eval.run_eval {' '.join(argv if argv is not None else sys.argv[1:])}`",
             "- runner=fixture replays recorded sandbox runs (stub): fast and deterministic, but it is NOT a live measurement. Use `make eval-live` for the pitch numbers.",
             f"- {results['n_malicious']} malicious / {n_clean} clean. FP shown as k/n with Wilson 95% CI: 0/{n_clean} is NOT a 0% rate.", "",
             "| tool | TP | FN | FP (k/n, 95% CI) | TN | inconclusive | precision | recall | F1 | median s |", "|---|---|---|---|---|---|---|---|---|---|"]
    for t, m in results["tools"].items():
        if t in unavailable:
            lines.append(f"| {t} | not run | | | | | | | | baseline unavailable on this machine (see DEPENDENCIES.md) |")
            continue
        ci = m["fp_rate_wilson95"]
        lines.append(f'| {t} | {m["tp"]} | {m["fn"]} | {m["fp"]}/{m["fp"] + m["tn"]} {ci} | {m["tn"]} | {m["inconclusive"]} | {m["precision"]} | {m["recall"]} | {m["f1"]} | {m["median_runtime_s"]} |')
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    if unavailable:
        print(f"note: baseline(s) not run (unavailable): {', '.join(unavailable)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
