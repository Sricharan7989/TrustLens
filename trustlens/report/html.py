"""Dev D: self-contained HTML report (no external assets, 100% offline).
Renders verdict hero, claims vs capabilities panel, phase x profile timeline lanes,
findings with visual evidence chains, and an honest coverage & abstention block.

All dynamic text MUST pass through esc() (package READMEs, payloads, and metadata are attacker-controlled).
"""
from __future__ import annotations

from html import escape


def esc(val: object) -> str:
    """Strict HTML escaping for untrusted attacker-controlled inputs."""
    if val is None:
        return ""
    return escape(str(val), quote=True)


CSS = """
:root {
  --bg: #0f172a;
  --surface: #1e293b;
  --surface-alt: #334155;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --border: #475569;
  --pass: #10b981;
  --pass-bg: rgba(16, 185, 129, 0.15);
  --review: #f59e0b;
  --review-bg: rgba(245, 158, 11, 0.15);
  --block: #ef4444;
  --block-bg: rgba(239, 68, 68, 0.15);
  --info: #3b82f6;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 2rem 1rem;
}
.container { max-width: 1100px; margin: 0 auto; }
.banner-stub {
  background: #78350f;
  color: #fef3c7;
  border: 1px solid #d97706;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  font-size: 0.9rem;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}
.header-grid {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 1.5rem;
}
.pkg-title h1 {
  font-size: 1.8rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.pkg-title .version {
  color: var(--text-muted);
  font-weight: 400;
  font-size: 1.2rem;
}
.meta-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
  font-size: 0.8rem;
}
.tag {
  background: var(--surface-alt);
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  color: var(--text-muted);
}
.badge-verdict {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-end;
  padding: 0.75rem 1.25rem;
  border-radius: 8px;
  font-weight: 700;
  text-align: right;
}
.badge-verdict.BLOCK { background: var(--block-bg); border: 2px solid var(--block); color: var(--block); }
.badge-verdict.REVIEW { background: var(--review-bg); border: 2px solid var(--review); color: var(--review); }
.badge-verdict.PASS { background: var(--pass-bg); border: 2px solid var(--pass); color: var(--pass); }
.verdict-action { font-size: 1.6rem; line-height: 1.1; letter-spacing: 0.05em; }
.verdict-name { font-size: 0.9rem; font-weight: 600; opacity: 0.9; }

.stats-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1rem;
  margin-top: 1.25rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--border);
}
.stat-item { font-size: 0.85rem; }
.stat-label { color: var(--text-muted); margin-bottom: 0.2rem; }
.stat-val { font-size: 1.2rem; font-weight: 600; font-family: var(--font-mono); }

.summary-box {
  background: rgba(255, 255, 255, 0.03);
  border-left: 4px solid var(--border);
  padding: 1rem 1.25rem;
  margin-top: 1rem;
  border-radius: 0 6px 6px 0;
  font-size: 1rem;
}
.summary-box.BLOCK { border-left-color: var(--block); }
.summary-box.REVIEW { border-left-color: var(--review); }
.summary-box.PASS { border-left-color: var(--pass); }

h2 {
  font-size: 1.3rem;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.section-subtitle {
  color: var(--text-muted);
  font-size: 0.85rem;
  margin-top: -0.5rem;
  margin-bottom: 1rem;
}

/* Findings & Evidence Chains */
.finding-card {
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--border);
  border-left: 5px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}
.finding-card.critical { border-left-color: #ef4444; }
.finding-card.high { border-left-color: #f87171; }
.finding-card.medium { border-left-color: #fbbf24; }
.finding-card.low { border-left-color: #60a5fa; }
.finding-card.info { border-left-color: #94a3b8; }

.finding-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}
.finding-title {
  font-size: 1.1rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.finding-pills { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.pill {
  font-size: 0.75rem;
  padding: 0.15rem 0.5rem;
  border-radius: 9999px;
  font-weight: 600;
  text-transform: uppercase;
}
.pill.severity-critical { background: #991b1b; color: #fee2e2; }
.pill.severity-high { background: #b91c1c; color: #fee2e2; }
.pill.severity-medium { background: #92400e; color: #fef3c7; }
.pill.severity-low { background: #1e40af; color: #dbeafe; }
.pill.canary { background: #4c1d95; color: #ede9fe; }
.pill.diff { background: #065f46; color: #d1fae5; }

.evidence-chain {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  margin: 1rem 0;
  padding: 0.85rem;
  background: rgba(0, 0, 0, 0.25);
  border-radius: 6px;
  font-size: 0.88rem;
}
.chain-node {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
}
.node-label {
  min-width: 100px;
  color: var(--text-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  font-weight: 700;
}
.node-val { flex: 1; font-family: var(--font-mono); font-size: 0.85rem; word-break: break-all; }
.chain-arrow { color: var(--text-muted); padding-left: 50px; font-size: 0.8rem; }

.finding-desc {
  color: #cbd5e1;
  font-size: 0.9rem;
  margin-top: 0.5rem;
  line-height: 1.5;
}

/* Timeline */
.timeline-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-top: 1rem;
}
.timeline-lane {
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
}
.lane-title {
  font-size: 0.85rem;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 700;
  margin-bottom: 0.5rem;
}
.lane-phases {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 0.5rem;
}
.phase-col {
  background: var(--surface-alt);
  border-radius: 4px;
  padding: 0.5rem;
  font-size: 0.8rem;
}
.phase-col h4 {
  font-size: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  padding-bottom: 0.25rem;
  margin-bottom: 0.4rem;
}
.event-dot {
  padding: 0.2rem 0.4rem;
  border-radius: 3px;
  font-size: 0.7rem;
  font-family: var(--font-mono);
  margin-bottom: 0.3rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: block;
}
.dot-succeeded { background: #991b1b; color: #fee2e2; }
.dot-blocked { background: #92400e; color: #fef3c7; }
.dot-clean { background: rgba(255, 255, 255, 0.1); color: var(--text-muted); }

/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 0.75rem 0; }
th, td { padding: 0.6rem 0.75rem; text-align: left; border: 1px solid var(--border); }
th { background: var(--surface-alt); color: var(--text-muted); font-weight: 600; }
td { background: rgba(0, 0, 0, 0.15); }
code { font-family: var(--font-mono); background: rgba(0, 0, 0, 0.3); padding: 0.15rem 0.35rem; border-radius: 3px; font-size: 0.85em; }

/* Coverage */
.coverage-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 0.75rem;
  list-style: none;
  margin-bottom: 1rem;
}
.coverage-item {
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem;
  font-size: 0.85rem;
}
.cov-title { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem; }
.cov-val { font-weight: 600; font-family: var(--font-mono); }

.not-observed-box {
  background: rgba(245, 158, 11, 0.05);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 6px;
  padding: 1rem;
  font-size: 0.85rem;
}
.not-observed-box h4 { color: var(--review); margin-bottom: 0.5rem; }
.not-observed-box ul { padding-left: 1.25rem; color: #cbd5e1; }

.footer {
  text-align: center;
  color: var(--text-muted);
  font-size: 0.8rem;
  padding: 2rem 0 1rem;
  border-top: 1px solid var(--border);
  margin-top: 2rem;
}
"""


def render_html(verdict: dict, fingerprint: dict | None = None, claims: dict | None = None) -> str:
    """Render self-contained, offline HTML report from verdict, fingerprint, and claims dicts."""
    p = verdict.get("package", {})
    cov = verdict.get("coverage", {})
    action = verdict.get("action", "REVIEW")
    verdict_name = verdict.get("verdict", "INCONCLUSIVE")
    score = verdict.get("score", 0.0)
    confidence = verdict.get("confidence", "low")
    summary = verdict.get("summary", "")
    findings = verdict.get("findings") or []
    signals = verdict.get("independent_signals") or []

    is_stub = False
    if fingerprint and fingerprint.get("run", {}).get("stub"):
        is_stub = True

    h = [
        "<!doctype html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        f"<title>TrustLens: {esc(p.get('name', 'Package'))} {esc(p.get('version', ''))}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
    ]

    # Stub / Recorded warning banner
    if is_stub:
        h.append(
            "<div class='banner-stub'>"
            "<span>[!]</span> <strong>RECORDED FIXTURE RUN:</strong> "
            "Behavior was replayed from a recorded fixture in schemas/examples, not freshly executed in bwrap."
            "</div>"
        )

    # Hero Header Card
    h.append("<div class='card'>")
    h.append("<div class='header-grid'>")
    h.append("<div class='pkg-title'>")
    h.append(f"<h1>{esc(p.get('name', 'unknown'))} <span class='version'>{esc(p.get('version', ''))}</span></h1>")
    h.append("<div class='meta-tags'>")
    h.append(f"<span class='tag'>ecosystem: {esc(p.get('ecosystem', 'pypi'))}</span>")
    if p.get("sha256"):
        h.append(f"<span class='tag'>sha256: <code>{esc(p.get('sha256')[:16])}...</code></span>")
    if p.get("path"):
        h.append(f"<span class='tag'>path: {esc(p.get('path'))}</span>")
    h.append("</div></div>")

    # Verdict Badge
    h.append(f"<div class='badge-verdict {esc(action)}'>")
    h.append(f"<span class='verdict-action'>{esc(action)}</span>")
    h.append(f"<span class='verdict-name'>{esc(verdict_name)}</span>")
    h.append("</div></div>")

    # Stats Bar
    h.append("<div class='stats-bar'>")
    h.append(f"<div class='stat-item'><div class='stat-label'>Risk Score</div><div class='stat-val'>{score:.1f} / 100</div></div>")
    h.append(f"<div class='stat-item'><div class='stat-label'>Confidence</div><div class='stat-val'>{esc(confidence.upper())}</div></div>")
    h.append(f"<div class='stat-item'><div class='stat-label'>Independent Signals</div><div class='stat-val'>{len(signals)}</div></div>")
    h.append(f"<div class='stat-item'><div class='stat-label'>Findings Count</div><div class='stat-val'>{len(findings)}</div></div>")
    h.append("</div>")

    # Summary Sentence
    h.append(f"<div class='summary-box {esc(action)}'><strong>Summary:</strong> {esc(summary)}</div>")
    h.append("</div>")  # end card

    # Claims vs Capabilities Panel
    h.append("<div class='card'>")
    h.append("<h2>Declared Claims &amp; Stated Purpose</h2>")
    h.append("<p class='section-subtitle'>Rule-based extraction from package README and metadata</p>")

    if claims and claims.get("intents"):
        h.append("<table><tr><th>Intent Category</th><th>Stated Quote</th><th>Source</th><th>Confidence</th></tr>")
        for i in claims["intents"]:
            h.append(
                f"<tr><td><code>{esc(i.get('intent'))}</code></td>"
                f"<td>&ldquo;{esc(i.get('quote'))}&rdquo;</td>"
                f"<td>{esc(i.get('source'))}</td>"
                f"<td>{int(float(i.get('confidence', 0.5)) * 100)}%</td></tr>"
            )
        h.append("</table>")
    elif claims and claims.get("unknown_intent"):
        h.append("<div class='summary-box REVIEW'>[!] <strong>Unknown Intent:</strong> No recognizable capability claims found in README or metadata. No sensitive actions licensed; any sensitive capability will trigger a review.</div>")
    else:
        h.append("<p style='color: var(--text-muted); font-size: 0.9rem;'>No explicit capability claims were extracted.</p>")
    h.append("</div>")

    # Findings with Evidence Chains
    h.append("<div class='card'>")
    h.append(f"<h2>Findings &amp; Evidence Chains ({len(findings)})</h2>")
    h.append("<p class='section-subtitle'>Observed behaviors minus claimed capabilities, verified with evidence chains</p>")

    if not findings:
        h.append("<p style='color: var(--pass); font-weight: 500;'>&check; No contradictory or suspicious findings detected within observed coverage.</p>")
    else:
        for f in findings:
            sev = esc(f.get("severity", "medium").lower())
            h.append(f"<div class='finding-card {sev}'>")
            h.append("<div class='finding-head'>")
            h.append(f"<div class='finding-title'><span>[{esc(f.get('severity', '').upper())}]</span> {esc(f.get('title', ''))}</div>")
            h.append("<div class='finding-pills'>")
            h.append(f"<span class='pill severity-{sev}'>{esc(f.get('rule', ''))}</span>")
            h.append(f"<span class='pill'>{esc(f.get('signal_class', ''))}</span>")
            if f.get("canary_hit"):
                h.append("<span class='pill canary'>Canary Hit</span>")
            if f.get("env_differential"):
                h.append("<span class='pill diff'>Env Differential</span>")
            h.append("</div></div>")

            # Evidence Chain Flow
            claim_info = f.get("claim", {})
            h.append("<div class='evidence-chain'>")
            if claim_info:
                h.append(f"<div class='chain-node'><span class='node-label'>1. Claim</span><span class='node-val'>&ldquo;{esc(claim_info.get('quote', ''))}&rdquo; ({esc(claim_info.get('status', ''))})</span></div>")
                h.append("<div class='chain-arrow'>&darr;</div>")

            evidence_items = f.get("evidence") or []
            if evidence_items:
                ev_str = " &rarr; ".join(f"{esc(e.get('phase'))}/{esc(e.get('profile'))} at {esc(str(e.get('file', '')))}:{esc(str(e.get('line', '')))} [{esc(e.get('outcome', ''))}]" for e in evidence_items)
                h.append(f"<div class='chain-node'><span class='node-label'>2. Observed</span><span class='node-val'>{ev_str}</span></div>")

                for ev in evidence_items:
                    det = ev.get("detail", {})
                    det_preview = esc(str(det.get("path") or det.get("url") or det.get("name") or det.get("dest") or det)[:140])
                    canary_txt = " [CANARY IN PAYLOAD]" if det.get("canary_in_bytes") else ""
                    h.append("<div class='chain-arrow'>&darr;</div>")
                    h.append(f"<div class='chain-node'><span class='node-label'>3. Evidence</span><span class='node-val'><code>{det_preview}{esc(canary_txt)}</code></span></div>")

            h.append("</div>")

            # Explanation
            h.append(f"<div class='finding-desc'>{esc(f.get('explanation', ''))}</div>")
            h.append("</div>")  # end finding-card
    h.append("</div>")  # end findings card

    # Timeline by Phase x Profile
    if fingerprint and fingerprint.get("events"):
        events = fingerprint["events"]
        h.append("<div class='card'>")
        h.append("<h2>Execution Timeline (Phase &times; Profile)</h2>")
        h.append("<p class='section-subtitle'>Differential execution trace across dev and ci environments</p>")

        profiles_present = sorted({e.get("profile", "dev") for e in events})
        phases_present = ["install", "startup", "fresh_startup", "import", "call", "cli"]

        h.append("<div class='timeline-grid'>")
        for prof in profiles_present:
            h.append(f"<div class='timeline-lane'><div class='lane-title'>Environment Profile: {esc(prof)}</div>")
            h.append("<div class='lane-phases'>")
            for ph in phases_present:
                ph_events = [e for e in events if e.get("profile") == prof and (e.get("phase") == ph or (ph == "startup" and e.get("phase") == "fresh_startup"))]
                if ph_events:
                    h.append(f"<div class='phase-col'><h4>{esc(ph)} ({len(ph_events)})</h4>")
                    for ev in ph_events:
                        dot_cls = "dot-succeeded" if ev.get("outcome") == "succeeded" and ev.get("canary_hit") else ("dot-blocked" if ev.get("outcome") == "blocked" else "dot-clean")
                        d = ev.get("detail", {})
                        snip = str(d.get("path") or d.get("url") or d.get("dest") or ev.get("capability") or "")[:40]
                        canary_tag = " [canary]" if ev.get("canary_hit") else ""
                        h.append(f"<span class='event-dot {dot_cls}' title='{esc(str(d))}'>{esc(ev.get('capability', ''))}: {esc(snip)}{esc(canary_tag)}</span>")
                    h.append("</div>")
            h.append("</div></div>")
        h.append("</div>")

        h.append("<details style='margin-top: 1rem;'><summary style='cursor: pointer; color: var(--info); font-size: 0.9rem;'>View Full Raw Event Timeline Table</summary>")
        h.append("<table><tr><th>#</th><th>Profile</th><th>Phase</th><th>Capability</th><th>Detail</th><th>Outcome</th><th>Canaries</th></tr>")
        for e in events:
            d = e.get("detail", {})
            txt = str(d.get("path") or d.get("name") or d.get("dest") or d.get("host") or d.get("url") or d.get("decoded_snippet") or d)[:100]
            outc = esc(e.get("outcome", ""))
            canary_str = esc(", ".join(e.get("canary_ids", [])))
            h.append(
                f"<tr><td>{e.get('seq')}</td><td><code>{esc(e.get('profile'))}</code></td>"
                f"<td>{esc(e.get('phase'))}</td><td><code>{esc(e.get('capability'))}</code></td>"
                f"<td><code>{esc(txt)}</code></td><td>{outc}</td><td>{canary_str}</td></tr>"
            )
        h.append("</table></details>")
        h.append("</div>")

    # Honest Coverage & Abstention Block
    h.append("<div class='card'>")
    h.append("<h2>Coverage &amp; Honest Abstention</h2>")
    h.append("<p class='section-subtitle'>Transparent boundary of what was observed vs. what was not executed</p>")

    h.append("<ul class='coverage-list'>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Phases Executed</div><div class='cov-val'>{esc(', '.join(cov.get('phases_run', [])))}</div></li>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Profiles Executed</div><div class='cov-val'>{esc(', '.join(cov.get('profiles_run', [])))}</div></li>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Triggers Run</div><div class='cov-val'>{esc(', '.join(cov.get('triggers_run', [])))}</div></li>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Callables Exercised</div><div class='cov-val'>{cov.get('callables_exercised', 0)} / {cov.get('callables_total', 0)}</div></li>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Network Policy</div><div class='cov-val'>{esc(cov.get('network', 'blocked'))}</div></li>")
    h.append(f"<li class='coverage-item'><div class='cov-title'>Install Diff Completed</div><div class='cov-val'>{'YES' if cov.get('install_completed') else 'NO'}</div></li>")
    h.append("</ul>")

    not_obs = cov.get("not_observed", [])
    if not_obs:
        h.append("<div class='not-observed-box'>")
        h.append("<h4>[!] Explicitly Not Observed (Known Blind Spots):</h4>")
        h.append("<ul>")
        for item in not_obs:
            h.append(f"<li>{esc(item)}</li>")
        h.append("</ul></div>")

    h.append("</div>")  # end coverage card

    # Footer
    h.append(
        "<div class='footer'>"
        "<p>Generated by <strong>TrustLens AI</strong> &middot; Rule-based, offline, deterministic provenance verification.</p>"
        "<p>Verdicts describe observed behaviour within the stated coverage; they are not proof of safety.</p>"
        "</div>"
    )

    h.append("</div></body></html>")
    return "\n".join(h)
