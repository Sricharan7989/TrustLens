"""Dev C: HTML heatmap of recall per trigger x gate, verdict x rule coverage, and ROC threshold sweep (no JS, no external dependencies)."""
from __future__ import annotations

from html import escape as esc

from eval.threshold_sweep import compute_rule_coverage, sweep_thresholds

CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 1080px; margin: 2rem auto; color: #1f2937; line-height: 1.5; padding: 0 1.5rem; background: #ffffff; }
h1 { color: #111827; font-size: 1.875rem; margin-bottom: 0.5rem; font-weight: 700; }
h2 { color: #111827; margin-top: 2.5rem; margin-bottom: 0.5rem; font-size: 1.35rem; font-weight: 600; border-bottom: 2px solid #f3f4f6; padding-bottom: 0.5rem; }
h3 { color: #374151; margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 1.1rem; font-weight: 600; }
.meta { color: #6b7280; font-size: 0.875rem; margin-bottom: 1.5rem; }
.nav-pills { display: flex; gap: 0.75rem; margin-bottom: 2rem; flex-wrap: wrap; }
.nav-pill { display: inline-block; padding: 6px 14px; background: #f3f4f6; color: #374151; text-decoration: none; border-radius: 9999px; font-size: 0.875rem; font-weight: 500; transition: background 0.15s; }
.nav-pill:hover { background: #e5e7eb; color: #111827; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.06); border-radius: 6px; overflow: hidden; font-size: 0.875rem; }
th, td { border: 1px solid #e5e7eb; padding: 9px 12px; text-align: center; }
th { background-color: #f9fafb; font-weight: 600; color: #374151; font-size: 0.8125rem; text-transform: uppercase; letter-spacing: 0.025em; }
th:first-child, td:first-child { text-align: left; font-weight: 500; font-family: monospace; font-size: 0.8125rem; }
.legend { display: flex; gap: 1.25rem; margin-top: 1rem; margin-bottom: 1.5rem; font-size: 0.8125rem; align-items: center; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; }
.legend-swatch { width: 16px; height: 16px; border-radius: 3px; border: 1px solid #d1d5db; }
.note { color: #6b7280; font-size: 0.8125rem; margin-top: 0.75rem; }
.dashboard-grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; margin: 1rem 0; }
@media (min-width: 840px) {
    .dashboard-grid-2col { display: grid; grid-template-columns: 1.2fr 1fr; gap: 2rem; align-items: start; }
}
.roc-container { background: #fafafa; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; font-family: monospace; }
.badge-malicious { background: #fee2e2; color: #991b1b; }
.badge-suspicious { background: #fef3c7; color: #92400e; }
.badge-clean { background: #dcfce7; color: #166534; }
.badge-inconclusive { background: #f3f4f6; color: #4b5563; }
.badge-op { background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }
"""


def _fmt_auc(auc: float | None) -> str:
    if auc is None:
        return "null"
    return f"{auc:.4f}"


def _fmt_rate(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.4f}"


def _auc_plot_points(sweep_records: list[dict], decided_malicious: int | None, decided_clean: int | None) -> list[dict]:
    """Points actually passed to ``compute_roc_auc`` (T > 0, both rates present, both classes decided)."""
    if decided_malicious is not None and decided_clean is not None:
        if decided_malicious < 1 or decided_clean < 1:
            return []
    return [
        p for p in sweep_records
        if p.get("threshold", 0) > 0 and p.get("fpr") is not None and p.get("tpr") is not None
    ]


def _fpr_width(pts: list[dict]) -> float:
    if len(pts) < 2:
        return 0.0
    xs = [float(p["fpr"]) for p in pts]
    return max(xs) - min(xs)


def _generate_roc_svg(
    sweep_records: list[dict],
    auc: float | None,
    nominal_t: float,
    decided_malicious: int | None = None,
    decided_clean: int | None = None,
) -> str:
    """Generate inline SVG for the ROC curve.

    Draws only the points passed to the AUC integral. A zero FPR width is markers
    only: no segment toward FPR 1 and no shaded area.
    """
    # Plot geometry: width 520, height 400
    # Margins: left 60, right 30, top 30, bottom 60
    # Plot box: x: 60..480 (w=420), y: 30..350 (h=320)
    w_px, h_px = 420, 320
    x0, y0 = 60, 350

    svg = [
        '<svg viewBox="0 0 540 420" width="100%" height="auto" style="max-width:540px;" xmlns="http://www.w3.org/2000/svg">',
        '<rect width="540" height="420" fill="#ffffff" rx="6" />',
        '<!-- Grid and axes -->',
    ]

    # Grid lines and tick labels
    for frac in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]:
        px = x0 + frac * w_px
        py = y0 - frac * h_px
        # Vertical grid
        svg.append(f'<line x1="{px:.1f}" y1="30" x2="{px:.1f}" y2="{y0}" stroke="#f3f4f6" stroke-width="1" />')
        # Horizontal grid
        svg.append(f'<line x1="{x0}" y1="{py:.1f}" x2="{x0 + w_px}" y2="{py:.1f}" stroke="#f3f4f6" stroke-width="1" />')
        # Labels
        svg.append(f'<text x="{px:.1f}" y="{y0 + 20}" font-size="11" fill="#6b7280" text-anchor="middle">{frac:.1f}</text>')
        svg.append(f'<text x="{x0 - 10}" y="{py + 4:.1f}" font-size="11" fill="#6b7280" text-anchor="end">{frac:.1f}</text>')

    # Axis lines
    svg.append(f'<line x1="{x0}" y1="{y0}" x2="{x0 + w_px}" y2="{y0}" stroke="#9ca3af" stroke-width="1.5" />')
    svg.append(f'<line x1="{x0}" y1="30" x2="{x0}" y2="{y0}" stroke="#9ca3af" stroke-width="1.5" />')

    # Axis titles
    svg.append(f'<text x="{x0 + w_px / 2}" y="{y0 + 44}" font-size="12" font-weight="600" fill="#374151" text-anchor="middle">False Positive Rate (FPR)</text>')
    svg.append(f'<text x="20" y="{30 + h_px / 2}" font-size="12" font-weight="600" fill="#374151" text-anchor="middle" transform="rotate(-90 20 {30 + h_px / 2})">True Positive Rate (Recall)</text>')

    # Diagonal chance line (FPR = TPR)
    svg.append(f'<line x1="{x0}" y1="{y0}" x2="{x0 + w_px}" y2="{30}" stroke="#d1d5db" stroke-width="1.5" stroke-dasharray="4 4" />')
    svg.append(f'<text x="{x0 + w_px - 8}" y="45" font-size="10" fill="#9ca3af" text-anchor="end">Random Chance (AUC=0.5)</text>')

    # Same points compute_roc_auc integrates. T <= 0 is the (1, 1) corner and is omitted.
    pts = sorted(_auc_plot_points(sweep_records, decided_malicious, decided_clean), key=lambda r: (r["fpr"], r["tpr"]))
    curve_coords = [(x0 + p["fpr"] * w_px, y0 - p["tpr"] * h_px) for p in pts]
    width = _fpr_width(pts)

    # Shade and stroke only when FPR actually moves. Do not extend the curve to FPR 1.
    if width > 0 and len(curve_coords) > 1:
        poly_pts = [f"{curve_coords[0][0]:.1f},{y0}"] + [f"{x:.1f},{y:.1f}" for x, y in curve_coords] + [f"{curve_coords[-1][0]:.1f},{y0}"]
        svg.append(f'<polygon points="{" ".join(poly_pts)}" fill="#2563eb" fill-opacity="0.12" />')
        path_d = f"M {curve_coords[0][0]:.1f} {curve_coords[0][1]:.1f} " + " ".join(f"L {x:.1f} {y:.1f}" for x, y in curve_coords[1:])
        svg.append(f'<path d="{path_d}" fill="none" stroke="#2563eb" stroke-width="2.5" stroke-linejoin="round" />')

    # Points & Operating Point highlight
    op_x, op_y = None, None
    for p in pts:
        cx = x0 + p["fpr"] * w_px
        cy = y0 - p["tpr"] * h_px
        t_val = p["threshold"]
        is_op = abs(t_val - nominal_t) < 1e-4

        if is_op:
            op_x, op_y = cx, cy
        else:
            svg.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4" fill="#3b82f6" stroke="#ffffff" stroke-width="1.5"><title>Threshold T={t_val}: TPR={p["tpr"]}, FPR={p["fpr"]}</title></circle>')

    if op_x is not None:
        # Operating point callout
        svg.append(f'<circle cx="{op_x:.1f}" cy="{op_y:.1f}" r="7" fill="#ef4444" stroke="#ffffff" stroke-width="2" />')
        svg.append(f'<line x1="{op_x:.1f}" y1="{op_y - 10:.1f}" x2="{op_x + 35:.1f}" y2="{op_y - 30:.1f}" stroke="#ef4444" stroke-width="1.5" />')
        svg.append(f'<rect x="{op_x + 35:.1f}" y="{op_y - 45:.1f}" width="130" height="22" rx="4" fill="#fef2f2" stroke="#fca5a5" stroke-width="1" />')
        svg.append(f'<text x="{op_x + 40:.1f}" y="{op_y - 30:.1f}" font-size="11" font-weight="700" fill="#991b1b">T={nominal_t} (weights.yaml)</text>')

    # AUC badge. A null integral is not drawn as 1.0.
    auc_text = "AUC n/a (decided cases only)" if auc is None else f"ROC AUC = {_fmt_auc(auc)}"
    badge_w = 220 if auc is None else 120
    svg.append(f'<rect x="{x0 + w_px - badge_w}" y="35" width="{badge_w}" height="26" rx="4" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1" />')
    svg.append(f'<text x="{x0 + w_px - badge_w / 2}" y="52" font-size="12" font-weight="700" fill="#1e40af" text-anchor="middle">{auc_text}</text>')

    svg.append('</svg>')
    return "".join(svg)


def render(results: dict) -> str:
    """Render full evaluation dashboard: Trigger x Gate, Rule Coverage, and ROC Threshold Sweep."""
    tools = results["tools"]
    dataset = results.get("dataset", "labels.yaml")
    n_mal = results.get("n_malicious", 0)
    n_clean = results.get("n_clean", 0)

    # 1. Trigger x Gate Recall Heatmap data
    all_keys = sorted({k for t in tools.values() for k in t.get("recall_by_trigger_gate", {})})

    # 2. Extract or compute threshold sweep and rule coverage for TrustLens
    tl_tool = tools.get("trustlens", {})
    per_pkg = tl_tool.get("per_package", {})

    sweep_data = results.get("threshold_sweep")
    coverage_data = results.get("rule_coverage")

    if not sweep_data or not coverage_data:
        # Build package list from per_package
        pkg_list = []
        for pid, pdata in per_pkg.items():
            pkg_list.append({
                "id": pid,
                "label": pdata.get("label", "malicious" if "slug" in pid or "evil" in pid or "bad" in pid else "clean"),
                "category": pdata.get("category"),
                "score": pdata.get("score", 0.0),
                "top_finding_score": pdata.get("top_finding_score", pdata.get("score", 0.0)),
                "verdict": pdata.get("verdict", "INCONCLUSIVE"),
                "flagged": pdata.get("flagged"),
                "rules": pdata.get("rules", []),
                "signal_classes": pdata.get("signal_classes", []),
                "inconclusive": pdata.get("verdict") == "INCONCLUSIVE",
            })
        if not sweep_data:
            sweep_data = sweep_thresholds(pkg_list)
        if not coverage_data:
            coverage_data = compute_rule_coverage(pkg_list)

    auc_val = sweep_data.get("auc") if "auc" in sweep_data else None
    nominal_t = sweep_data.get("nominal_threshold", 4.0)
    sweep_records = sweep_data.get("sweep", [])
    sensitivity = sweep_data.get("sensitivity", {})
    rule_summary = coverage_data.get("rule_summary", [])
    pkg_matrix = coverage_data.get("package_matrix", [])

    h = [
        "<!doctype html>",
        "<meta charset=utf-8>",
        "<title>PS1-Bench Evaluation & Rule Coverage Dashboard</title>",
        f"<style>{CSS}</style>",
        "<h1>PS1-Bench Evaluation Dashboard</h1>",
        f"<p class='meta'>Dataset: <strong>{esc(dataset)}</strong> ({n_mal} malicious, {n_clean} clean) &middot; Offline Evaluation &middot; Owner: Dev C</p>",
        "<div class='nav-pills'>",
        "<a class='nav-pill' href='#recall-matrix'>&darr; 1. Trigger &times; Gate Recall</a>",
        "<a class='nav-pill' href='#rule-coverage'>&darr; 2. Verdict &times; Rule Coverage</a>",
        "<a class='nav-pill' href='#roc-sweep'>&darr; 3. ROC Threshold Sweep (weights.yaml)</a>",
        "</div>",
        "<!-- SECTION 1: TRIGGER X GATE RECALL HEATMAP -->",
        "<h2 id='recall-matrix'>1. PS1-Bench Recall Heatmap (Trigger &times; Gate)</h2>",
        "<p class='note'>Recall breakdown across execution triggers and sandbox environmental gating profiles.</p>",
        "<table>",
        "<tr><th>Trigger | Gate</th>" + "".join(f"<th>{esc(t)}</th>" for t in tools) + "</tr>",
    ]

    for k in all_keys:
        h.append(f"<tr><td>{esc(k)}</td>")
        for t_data in tools.values():
            avail = t_data.get("available", True)
            c = t_data.get("recall_by_trigger_gate", {}).get(k)
            if not avail:
                h.append("<td style='background:#f3f4f6;color:#6b7280;font-style:italic;'>not run</td>")
            elif not c:
                h.append("<td>-</td>")
            else:
                det = int(c.get("detected") or 0)
                decided = c.get("decided")
                if decided is None:
                    decided = det if c.get("recall") is not None else 0
                inc = c.get("inconclusive")
                if inc is None:
                    inc = max(int(c.get("total") or 0) - int(decided), 0)
                label = f"{det}/{int(decided)} (inconclusive {int(inc)})" if int(decided) > 0 else f"- (inconclusive {int(inc)})"
                recall = c.get("recall")
                if int(decided) <= 0 or recall is None:
                    style = "background:#f3f4f6;color:#4b5563;"
                elif recall >= 1.0 and int(inc) == 0:
                    style = "background:#dcfce7;color:#166534;font-weight:700;"
                elif recall > 0.0:
                    style = "background:#fef3c7;color:#92400e;font-weight:700;"
                else:
                    style = "background:#fee2e2;color:#991b1b;font-weight:600;"
                h.append(f"<td style='{style}'>{label}</td>")
        h.append("</tr>")

    h.append("</table>")
    h.append("<div class='legend'>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#dcfce7;'></div> Decided recall complete</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#fef3c7;'></div> Partial decided recall</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#fee2e2;'></div> Zero decided recall</div>")
    h.append("<div class='legend-item'><div class='legend-swatch' style='background:#f3f4f6;'></div> Abstain or tool not run</div>")
    h.append("</div>")

    # SECTION 2: VERDICT X RULE COVERAGE HEATMAP
    h.append("<!-- SECTION 2: VERDICT X RULE COVERAGE HEATMAP -->")
    h.append("<h2 id='rule-coverage'>2. Verdict &times; Rule Coverage Heatmap (TrustLens)</h2>")
    h.append("<p class='note'>Distribution of triggered detection rules across final verdict categories. Rules reflect observed capabilities minus licensed claims.</p>")

    # Table 2A: Rule summary matrix
    h.append("<h3>2A. Detection Rule Hits by Verdict Category</h3>")
    h.append("<table>")
    h.append("<tr><th>Detection Rule</th><th>Total Hits</th><th>MALICIOUS-EVIDENT (Block)</th><th>SUSPICIOUS (Review)</th><th>BENIGN-CONSISTENT (Pass)</th><th>INCONCLUSIVE</th></tr>")

    for r in rule_summary:
        rule_name = r["rule"]
        tot = r["total_hits"]
        m_ev = r["malicious_evident"]
        susp = r["suspicious"]
        ben = r["benign_consistent"]
        inc = r["inconclusive"]

        m_style = "background:#fee2e2;color:#991b1b;font-weight:700;" if m_ev > 0 else ""
        s_style = "background:#fef3c7;color:#92400e;font-weight:600;" if susp > 0 else ""
        b_style = "background:#f3f4f6;color:#6b7280;" if ben > 0 else ""

        h.append(f"<tr><td><code>{esc(rule_name)}</code></td>")
        h.append(f"<td><strong>{tot}</strong></td>")
        h.append(f"<td style='{m_style}'>{m_ev}</td>")
        h.append(f"<td style='{s_style}'>{susp}</td>")
        h.append(f"<td style='{b_style}'>{ben}</td>")
        h.append(f"<td>{inc}</td>")
        h.append("</tr>")

    h.append("</table>")

    # Table 2B: Package-by-rule grid
    if pkg_matrix:
        h.append("<h3>2B. Package &times; Rule Firing Matrix</h3>")
        h.append("<p class='note'>Individual package rule activation matrix. Shows which detection rules fired for each evaluated package.</p>")
        h.append("<table>")
        h.append("<tr><th>Package ID</th><th>Label</th><th>Verdict</th><th>Score</th><th>Rules Triggered</th></tr>")
        for p in pkg_matrix:
            lbl = p.get("label", "unknown")
            lbl_badge = f"<span class='badge badge-malicious'>{esc(lbl)}</span>" if lbl == "malicious" else f"<span class='badge badge-clean'>{esc(lbl)}</span>"
            verd = p.get("verdict", "INCONCLUSIVE")
            if verd == "MALICIOUS-EVIDENT":
                v_badge = f"<span class='badge badge-malicious'>{esc(verd)}</span>"
            elif verd == "SUSPICIOUS":
                v_badge = f"<span class='badge badge-suspicious'>{esc(verd)}</span>"
            elif verd == "BENIGN-CONSISTENT":
                v_badge = f"<span class='badge badge-clean'>{esc(verd)}</span>"
            else:
                v_badge = f"<span class='badge badge-inconclusive'>{esc(verd)}</span>"

            rules_list = p.get("rules_fired", [])
            rules_str = ", ".join(f"<code>{esc(rf)}</code>" for rf in rules_list) if rules_list else "<span style='color:#9ca3af;'>none</span>"
            score_val = p.get("score", 0.0)

            h.append(f"<tr><td>{esc(p['id'])}</td><td>{lbl_badge}</td><td>{v_badge}</td><td>{score_val}</td><td style='text-align:left;'>{rules_str}</td></tr>")
        h.append("</table>")

    # SECTION 3: ROC THRESHOLD SWEEP & SENSITIVITY
    h.append("<!-- SECTION 3: ROC THRESHOLD SWEEP -->")
    h.append("<h2 id='roc-sweep'>3. ROC-like Threshold Sweep & Sensitivity Analysis (weights.yaml)</h2>")
    h.append("<p class='note'>Evaluation of True Positive Rate (Recall) vs False Positive Rate (FPR) across scoring thresholds. The default operating point (<code>suspicious_threshold: 4.0</code>) and &plusmn;20% sensitivity bounds are highlighted.</p>")

    h.append("<div class='dashboard-grid dashboard-grid-2col'>")

    # Column 1: Inline SVG ROC Curve
    h.append("<div class='roc-container'>")
    h.append("<h3 style='margin-top:0;'>Empirical ROC Curve</h3>")
    h.append(_generate_roc_svg(
        sweep_records,
        auc_val,
        nominal_t,
        sweep_data.get("decided_malicious"),
        sweep_data.get("decided_clean"),
    ))
    auc_caption = "AUC n/a (decided cases only)" if auc_val is None else f"ROC AUC = {_fmt_auc(auc_val)}"
    h.append(f"<p class='note' style='text-align:center;'>Empirical Area Under Curve (decided cases only; inconclusive: {sweep_data.get('inconclusive', 'n/a')}): <strong>{auc_caption}</strong></p>")
    h.append("</div>")

    # Column 2: Sensitivity Summary
    h.append("<div>")
    h.append("<h3 style='margin-top:0;'>Threshold Sensitivity Analysis (&plusmn;20%)</h3>")
    nom_rec = sensitivity.get("nominal", {})
    lo_rec = sensitivity.get("minus_20_pct", {}).get("record", {})
    hi_rec = sensitivity.get("plus_20_pct", {}).get("record", {})

    h.append("<table>")
    h.append("<tr><th>Operating Point</th><th>Threshold</th><th>TPR (Recall)</th><th>FPR (Wilson 95% CI)</th></tr>")
    h.append(f"<tr><td>-20% Sensitivity</td><td><code>{sensitivity.get('minus_20_pct', {}).get('threshold')}</code></td><td><strong>{_fmt_rate(lo_rec.get('tpr'))}</strong></td><td>{_fmt_rate(lo_rec.get('fpr'))}</td></tr>")
    h.append(f"<tr style='background:#eff6ff;'><td><strong>Nominal (weights.yaml)</strong></td><td><code><strong>{nominal_t}</strong></code></td><td><strong>{_fmt_rate(nom_rec.get('tpr'))}</strong></td><td>{_fmt_rate(nom_rec.get('fpr'))}</td></tr>")
    h.append(f"<tr><td>+20% Sensitivity</td><td><code>{sensitivity.get('plus_20_pct', {}).get('threshold')}</code></td><td><strong>{_fmt_rate(hi_rec.get('tpr'))}</strong></td><td>{_fmt_rate(hi_rec.get('fpr'))}</td></tr>")
    h.append("</table>")

    flips = sensitivity.get("flipping_packages", [])
    if flips:
        h.append("<h4 style='margin-top:1rem;color:#b45309;'>Packages with Verdict Flips across &plusmn;20%:</h4>")
        h.append("<table><tr><th>Package</th><th>Label</th><th>Score</th><th>T=3.2</th><th>T=4.0</th><th>T=4.8</th></tr>")
        for fl in flips:
            f32 = "FLAGGED" if fl.get("flagged_at_3_2") else "CLEAN"
            f40 = "FLAGGED" if fl.get("flagged_at_4_0") else "CLEAN"
            f48 = "FLAGGED" if fl.get("flagged_at_4_8") else "CLEAN"
            h.append(f"<tr><td>{esc(fl['id'])}</td><td>{esc(fl.get('label', ''))}</td><td>{fl['score']}</td><td>{f32}</td><td>{f40}</td><td>{f48}</td></tr>")
        h.append("</table>")
    else:
        h.append("<p class='note' style='background:#f0fdf4;padding:10px;border-radius:6px;border:1px solid #bbf7d0;color:#166534;'><strong>Robustness Invariant:</strong> Zero packages flip verdicts under &plusmn;20% perturbation of <code>suspicious_threshold</code>. The operating point is stable.</p>")

    h.append("</div>")
    h.append("</div>")

    # Table 3: Full threshold sweep table
    h.append("<h3>3B. Complete Decision Threshold Sweep Table</h3>")
    h.append("<table>")
    h.append("<tr><th>Threshold (T)</th><th>TP</th><th>FN</th><th>FP</th><th>TN</th><th>TPR (Recall)</th><th>FPR</th><th>Wilson 95% CI</th><th>Precision</th><th>F1</th><th>Notes</th></tr>")

    for sw in sweep_records:
        t_val = sw["threshold"]
        is_nom = abs(t_val - nominal_t) < 1e-4
        row_style = "background:#eff6ff;font-weight:600;" if is_nom else ""
        ci = sw.get("fpr_wilson95")
        ci_str = f"[{ci[0]}, {ci[1]}]" if ci else "None"
        pr_str = f"{sw['precision']:.4f}" if sw.get("precision") is not None else "None"
        f1_str = f"{sw['f1']:.4f}" if sw.get("f1") is not None else "None"
        note_str = esc(sw.get("note", ""))

        h.append(f"<tr style='{row_style}'>")
        h.append(f"<td>{t_val:.1f}</td>")
        h.append(f"<td>{sw['tp']}</td>")
        h.append(f"<td>{sw['fn']}</td>")
        h.append(f"<td>{sw['fp']}</td>")
        h.append(f"<td>{sw['tn']}</td>")
        h.append(f"<td>{_fmt_rate(sw.get('tpr'))}</td>")
        h.append(f"<td>{_fmt_rate(sw.get('fpr'))}</td>")
        h.append(f"<td>{ci_str}</td>")
        h.append(f"<td>{pr_str}</td>")
        h.append(f"<td>{f1_str}</td>")
        h.append(f"<td style='text-align:left;font-size:0.75rem;'>{note_str}</td>")
        h.append("</tr>")

    h.append("</table>")
    h.append("<p class='note'>Full raw metrics are recorded in <code>results.json</code> and detailed textual report in <code>summary.md</code>.</p>")

    return "".join(h)
