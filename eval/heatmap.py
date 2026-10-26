"""Dev C: HTML heatmap of recall per trigger x gate per tool (no JS, no deps)."""
from __future__ import annotations

from html import escape as esc


def render(results: dict) -> str:
    tools = results["tools"]
    keys = sorted({k for t in tools.values() for k in t["recall_by_trigger_gate"]})
    h = ["<!doctype html><meta charset=utf-8><title>PS1-Bench recall heatmap</title><style>td,th{border:1px solid #ccc;padding:6px 10px;text-align:center}</style>",
         "<h2>Recall per trigger | gate</h2><table><tr><th>trigger | gate</th>" + "".join(f"<th>{esc(t)}</th>" for t in tools) + "</tr>"]
    for k in keys:
        h.append(f"<tr><td>{esc(k)}</td>")
        for t in tools.values():
            c = t["recall_by_trigger_gate"].get(k)
            if not c or c["recall"] is None:
                h.append("<td>-</td>")
            else:
                r = c["recall"]
                h.append(f"<td style='background:rgb({int(255 * (1 - r))},{int(200 * r + 55)},80)'>{c['detected']}/{c['total']}</td>")
        h.append("</tr>")
    h.append("</table><p>Precision/recall/F1, FP rate with Wilson 95% CI: see results.json.</p>")
    return "".join(h)
