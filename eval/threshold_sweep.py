"""Dev C: ROC-like threshold sweep and verdict x rule coverage using weights.yaml (read-only).

This module analyzes evaluation runs across detection score thresholds and evaluates:
1. True Positive Rate (Recall) vs False Positive Rate (FPR) across threshold sweeps (ROC curve + AUC).
2. Sensitivity of verdicts to +/- 20% perturbations in weights.yaml decision thresholds.
3. Rule coverage across verdict categories (MALICIOUS-EVIDENT, SUSPICIOUS, BENIGN-CONSISTENT, INCONCLUSIVE).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from eval.metrics import wilson

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS_FILE = ROOT / "trustlens" / "engine" / "weights.yaml"

ALL_RULES = [
    "canary_read_then_network",
    "canary_in_outgoing_bytes",
    "network_unclaimed",
    "decoded_exec",
    "env_differential",
    "startup_hook",
    "persistence",
    "download_exec",
    "capability_not_claimed",
    "sandbox_probe",
]

DEFAULT_THRESHOLDS = [0.0, 1.0, 2.0, 3.0, 3.2, 3.5, 4.0, 4.5, 4.8, 5.0, 6.0, 7.0, 8.0, 10.0, 12.0, 15.0]


def load_weights_readonly() -> dict:
    """Load engine weights.yaml in strict read-only mode."""
    if not WEIGHTS_FILE.exists():
        raise FileNotFoundError(f"weights.yaml not found at {WEIGHTS_FILE}")
    with open(WEIGHTS_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f.read())


def compute_roc_auc(points: list[dict[str, Any]]) -> float:
    """Compute Area Under the ROC Curve (AUC) using trapezoidal rule.

    Points must contain 'fpr' and 'tpr'.
    Sorts points by FPR ascending, TPR ascending.
    """
    if not points:
        return 0.0
    valid = [p for p in points if p.get("fpr") is not None and p.get("tpr") is not None]
    if not valid:
        return 0.0
    sorted_pts = sorted(valid, key=lambda p: (p["fpr"], p["tpr"]))
    pts = [(0.0, 0.0)]
    for p in sorted_pts:
        pts.append((p["fpr"], p["tpr"]))

    # Remove duplicates preserving order
    dedup: list[tuple[float, float]] = []
    for pt in pts:
        if not dedup or pt != dedup[-1]:
            dedup.append(pt)

    auc = 0.0
    for i in range(1, len(dedup)):
        x0, y0 = dedup[i - 1]
        x1, y1 = dedup[i]
        dx = x1 - x0
        if dx > 0:
            auc += dx * (y0 + y1) / 2.0
    return round(auc, 4)


def sweep_thresholds(
    package_evals: list[dict[str, Any]],
    weights: dict | None = None,
    thresholds: list[float] | None = None,
) -> dict:
    """Perform a threshold sweep across suspicious_threshold values.

    package_evals is a list of dicts with:
      - 'id': package id
      - 'label': 'malicious' or 'clean'
      - 'score': float (overall package finding score)
      - 'top_finding_score': float (max individual finding score)
      - 'verdict': str
      - 'rules': list of rule names
      - 'signal_classes': list of signal class strings
      - 'inconclusive': bool
    """
    if weights is None:
        weights = load_weights_readonly()

    if thresholds is None:
        thresholds = DEFAULT_THRESHOLDS

    default_t = float(weights.get("suspicious_threshold", 4.0))
    t_minus_20 = round(default_t * 0.8, 2)  # 3.2
    t_plus_20 = round(default_t * 1.2, 2)   # 4.8

    # Ensure operating points are in threshold list
    all_t = sorted(set(thresholds) | {default_t, t_minus_20, t_plus_20})

    strong_classes = set(weights.get("strong_signal_classes", []))
    block_min = int(weights.get("block_min_independent_signals", 2))
    sweep_records: list[dict] = []

    for t in all_t:
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        inc = 0

        for pkg in package_evals:
            lbl = pkg.get("label")
            is_inc = pkg.get("inconclusive", False) or pkg.get("verdict") == "INCONCLUSIVE"
            if is_inc:
                inc += 1
                continue

            # Sweep top_finding_score only; keep engine block rule (canary-in-bytes or >= 2 strong classes) as flagged at every T
            classes = set(c for c in pkg.get("signal_classes", []) if c in strong_classes)
            is_block = ("canary_in_bytes" in classes or len(classes) >= block_min)
            top_score = pkg.get("top_finding_score")
            score_flagged = bool(top_score is not None and top_score >= t)
            flagged = bool(is_block or score_flagged)

            if lbl == "malicious":
                if flagged:
                    tp += 1
                else:
                    fn += 1
            elif lbl == "clean":
                if flagged:
                    fp += 1
                else:
                    tn += 1

        tpr = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
        f1 = round(2 * prec * tpr / (prec + tpr), 4) if (prec and tpr and (prec + tpr) > 0) else None
        ci = wilson(fp, fp + tn)

        note = ""
        if t == default_t:
            note = f"Default threshold in weights.yaml ({default_t})"
        elif t == t_minus_20:
            note = f"-20% sensitivity threshold ({t_minus_20})"
        elif t == t_plus_20:
            note = f"+20% sensitivity threshold ({t_plus_20})"

        sweep_records.append({
            "threshold": t,
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "inconclusive": inc,
            "tpr": tpr,
            "recall": tpr,
            "fpr": fpr,
            "precision": prec,
            "f1": f1,
            "fpr_wilson95": ci,
            "note": note,
        })

    # Sensitivity delta
    def _find_rec(val: float) -> dict:
        return next((r for r in sweep_records if abs(r["threshold"] - val) < 1e-4), {})

    rec_def = _find_rec(default_t)
    rec_lo = _find_rec(t_minus_20)
    rec_hi = _find_rec(t_plus_20)

    sensitivity = {
        "nominal_threshold": default_t,
        "nominal": rec_def,
        "minus_20_pct": {"threshold": t_minus_20, "record": rec_lo, "delta_tpr": round((rec_lo.get("tpr", 0.0) - rec_def.get("tpr", 0.0)), 4), "delta_fpr": round((rec_lo.get("fpr", 0.0) - rec_def.get("fpr", 0.0)), 4)},
        "plus_20_pct": {"threshold": t_plus_20, "record": rec_hi, "delta_tpr": round((rec_hi.get("tpr", 0.0) - rec_def.get("tpr", 0.0)), 4), "delta_fpr": round((rec_hi.get("fpr", 0.0) - rec_def.get("fpr", 0.0)), 4)},
    }

    # Identify packages that change verdict between t_minus_20 and t_plus_20
    flips: list[dict] = []
    for pkg in package_evals:
        is_inc = pkg.get("inconclusive", False) or pkg.get("verdict") == "INCONCLUSIVE"
        if is_inc:
            continue
        classes = set(c for c in pkg.get("signal_classes", []) if c in strong_classes)
        is_block = ("canary_in_bytes" in classes or len(classes) >= block_min)
        if is_block:
            continue
        s = pkg.get("top_finding_score")
        if s is None:
            continue
        f_lo = bool(s >= t_minus_20)
        f_nom = bool(s >= default_t)
        f_hi = bool(s >= t_plus_20)
        if f_lo != f_hi:
            flips.append({
                "id": pkg["id"],
                "label": pkg.get("label"),
                "score": s,
                "flagged_at_3_2": f_lo,
                "flagged_at_4_0": f_nom,
                "flagged_at_4_8": f_hi,
            })

    sensitivity["flipping_packages"] = flips

    auc = compute_roc_auc(sweep_records)

    return {
        "weights_file": str(WEIGHTS_FILE.relative_to(ROOT)),
        "nominal_threshold": default_t,
        "auc": auc,
        "sweep": sweep_records,
        "sensitivity": sensitivity,
    }


def compute_rule_coverage(package_evals: list[dict[str, Any]]) -> dict:
    """Compute rule coverage matrix across verdict categories and per-package breakdown."""
    verdict_cats = ["MALICIOUS-EVIDENT", "SUSPICIOUS", "BENIGN-CONSISTENT", "INCONCLUSIVE"]

    # Rule frequency by verdict
    rule_counts: dict[str, dict[str, int]] = {r: {v: 0 for v in verdict_cats} for r in ALL_RULES}
    rule_pkg_ids: dict[str, dict[str, list[str]]] = {r: {v: [] for v in verdict_cats} for r in ALL_RULES}

    # Package-by-rule matrix
    pkg_matrix: list[dict] = []

    for pkg in package_evals:
        pkg_id = pkg["id"]
        v = pkg.get("verdict", "INCONCLUSIVE")
        if v not in verdict_cats:
            v = "INCONCLUSIVE"
        rules_fired = pkg.get("rules", [])
        # Count rules
        for r in rules_fired:
            if r in rule_counts:
                rule_counts[r][v] += 1
                rule_pkg_ids[r][v].append(pkg_id)
            else:
                # Discovered rule not in predefined list
                rule_counts.setdefault(r, {vc: 0 for vc in verdict_cats})[v] += 1
                rule_pkg_ids.setdefault(r, {vc: [] for vc in verdict_cats})[v].append(pkg_id)

        pkg_matrix.append({
            "id": pkg_id,
            "label": pkg.get("label"),
            "category": pkg.get("category"),
            "verdict": v,
            "score": pkg.get("score", 0.0),
            "flagged": pkg.get("flagged"),
            "rules_fired": rules_fired,
        })

    # Summary per rule
    rule_summary = []
    for r in sorted(rule_counts.keys()):
        counts = rule_counts[r]
        total_hits = sum(counts.values())
        rule_summary.append({
            "rule": r,
            "total_hits": total_hits,
            "malicious_evident": counts["MALICIOUS-EVIDENT"],
            "suspicious": counts["SUSPICIOUS"],
            "benign_consistent": counts["BENIGN-CONSISTENT"],
            "inconclusive": counts["INCONCLUSIVE"],
            "packages": rule_pkg_ids[r],
        })

    return {
        "verdict_categories": verdict_cats,
        "rule_summary": rule_summary,
        "package_matrix": pkg_matrix,
    }
