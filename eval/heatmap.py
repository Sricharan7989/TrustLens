"""Dev C: HTML heatmap of recall per trigger x gate per tool (no JS, no external dependencies)."""
from __future__ import annotations

from html import escape as esc

CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; color: #1f2937; line-height: 1.5; padding: 0 1rem; }
h2 { color: #111827; margin-bottom: 0.25rem; font-size: 1.5rem; }
.meta { color: #6b7280; font-size: 0.875rem; margin-bottom: 1.5rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; overflow: hidden; }
th, td { border: 1px solid #e5e7eb; padding: 10px 14px; text-align: center; }
th { background-color: #f9fafb; font-weight: 600; color: #374151; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.025em; }
th:first-child, td:first-child { text-align: left; font-weight: 500; font-family: monospace; font-size: 0.875rem; }
.legend { display: flex; gap: 1rem; margin-top: 1.5rem; font-size: 0.8125rem; align-items: center; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; }
.legend-swatch { width: 16px; height: 16px; border-radius: 3px; border: 1px solid #d1d5db; }
.note { color: #6b7280; font-size: 0.8125rem; margin-top: 1rem; }
"""


def render(results: dict) -> str:
    tools = results["tools"]
    dataset = results.get("dataset", "labels.yaml")
    n_mal = results.get("n_malicious", 0)
    n_clean = results.get("n_clean", 0)

    # All unique trigger|gate keys across all tools
    all_keys = sorted({k for t in tools.values() for k in t.get("recall_by_trigger_gate", {})})

    h = [
        "<!doctype html>",
        "<meta charset=utf-8>",
        "<title>PS1-Bench Recall Heatmap</title>",
        f"<style>{CSS}</style>",
        "<h2>PS1-Bench Recall Heatmap (Trigger &times; Gate)</h2>",
        f"<p class='meta'>Dataset: <strong>{esc(dataset)}</strong> ({n_mal} malicious, {n_clean} clean) &middot; Offline Evaluation</p>",
        "<table>",
        "<tr><th>Trigger | Gate</th>" + "".join(f"<th>{esc(t)}</th>" for t in tools) + "</tr>",
    ]

    for k in all_keys:
        h.append(f"<tr><td>{esc(k)}</td>")
        for t_data in tools.values():
            avail = t_data.get("available", True)
            c = t_data.get("recall_by_trigger_gate", {}).get(k)
            if not avail or not c or c.get("recall") is None:
                h.append("<td style='background:#f3f4f6;color:#6b7280;font-style:italic;'>not run</td>")
            else:
                r = c["recall"]
                det, tot = c["detected"], c["total"]
                if tot == 0:
                    h.append("<td>-</td>")
                elif r >= 1.0:
                    h.append(f"<td style='background:#dcfce7;color:#166534;font-weight:700;'>{det}/{tot} (100%)</td>")
                elif r > 0.0:
                    pct = int(r * 100)
                    h.append(f"<td style='background:#fef3c7;color:#92400e;font-weight:700;'>{det}/{tot} ({pct}%)</td>")
                else:
                    h.append(f"<td style='background:#fee2e2;color:#991b1b;font-weight:600;'>{det}/{tot} (0%)</td>")
        h.append("</tr>")

    h.append("</table>")
    h.append("<div class='legend'>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#dcfce7;'></div> High Recall (100%)</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#fef3c7;'></div> Partial Recall</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#fee2e2;'></div> Zero Recall</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#f3f4f6;'></div> Not Run / Inconclusive</div>")
    h.append("</div>")
    h.append("<p class='note'>Full metrics (TP, FP, TN, FN, Wilson 95% CI, Precision, Recall, F1) are available in <code>results.json</code> and <code>summary.md</code>.</p>")
    return "".join(h)
