"""Dev C: metrics. Pure functions, unit-tested (tests/bench/test_metrics.py)."""
from __future__ import annotations

import math
import statistics
from collections import defaultdict


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0.0, (c - m) / d), 4), round(min(1.0, (c + m) / d), 4)]


def _div(a: float, b: float) -> float | None:
    return round(a / b, 4) if b else None


def confusion(rows: list[dict]) -> dict:
    """rows: {label: 'malicious'|'clean', flagged: bool|None (None = inconclusive/unavailable), trigger, gate, runtime_s}."""
    tp = sum(1 for r in rows if r["label"] == "malicious" and r["flagged"] is True)
    fn = sum(1 for r in rows if r["label"] == "malicious" and r["flagged"] is not True)
    fp = sum(1 for r in rows if r["label"] == "clean" and r["flagged"] is True)
    tn = sum(1 for r in rows if r["label"] == "clean" and r["flagged"] is not True)
    inc = sum(1 for r in rows if r["flagged"] is None)
    prec, rec = _div(tp, tp + fp), _div(tp, tp + fn)
    f1 = round(2 * prec * rec / (prec + rec), 4) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    by = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["label"] == "malicious":
            key = f'{r.get("trigger")}|{r.get("gate")}'
            by[key][1] += 1
            by[key][0] += r["flagged"] is True
    rts = [r["runtime_s"] for r in rows if r.get("runtime_s") is not None]
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "inconclusive": inc, "precision": prec, "recall": rec, "f1": f1,
            "fp_rate": _div(fp, fp + tn), "fp_rate_wilson95": wilson(fp, fp + tn),
            "median_runtime_s": round(statistics.median(rts), 2) if rts else None,
            "recall_by_trigger_gate": {k: {"detected": v[0], "total": v[1], "recall": _div(v[0], v[1])} for k, v in sorted(by.items())}}
