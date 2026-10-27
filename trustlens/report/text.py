"""Dev D: terminal + JSON renderers."""
from __future__ import annotations

import json
import re

from trustlens.report.redact import has_canary_in_bytes, redact_text

COLORS = {"PASS": "\033[32m", "REVIEW": "\033[33m", "BLOCK": "\033[31m"}

_TAG_RE = re.compile(r"<[^>]+>")


def strip_controls(s: str) -> str:
    """Remove ESC/CSI/C1 and control characters (except tab, LF, CR), plus HTML tags."""
    return _TAG_RE.sub("", redact_text(s))


def _plain(value: object, *, urls: bool = False) -> str:
    """Terminal-safe text: controls, tags, and canary bytes removed. URLs too when canary bytes were seen."""
    return _TAG_RE.sub("", redact_text(value, urls=urls))


def render_json(verdict: dict, fingerprint: dict | None = None, claims: dict | None = None) -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "verdict": verdict,
            "claims": claims,
            "fingerprint": fingerprint,
        },
        indent=1,
    )


def render_text(verdict: dict, color: bool = False) -> str:
    c, r = (COLORS.get(verdict.get("action", ""), ""), "\033[0m") if color else ("", "")
    p = verdict.get("package", {})

    findings = verdict.get("findings") or []
    summary_urls = any(has_canary_in_bytes(f) for f in findings)
    pkg_name = _plain(p.get("name", ""))
    pkg_ver = _plain(p.get("version", ""))
    summary = _plain(verdict.get("summary", ""), urls=summary_urls)

    action = verdict.get("action", "")
    verd = verdict.get("verdict", "")
    score = verdict.get("score", 0)
    conf = verdict.get("confidence", "")

    lines = [
        f"{c}{action:6} {verd}{r}  {pkg_name} {pkg_ver}  (score {score}, confidence {conf})",
        "  " + summary,
    ]
    for f in findings[:6]:
        flagged = has_canary_in_bytes(f)
        title = _plain(f.get("title", ""), urls=flagged)
        expl = _plain(f.get("explanation", ""), urls=flagged)
        sev = f.get("severity", "")
        lines.append(f"  - [{sev}] {title}")
        lines.append(f"      {expl[:240]}")

    cov = verdict.get("coverage", {})
    phases = ",".join(cov.get("phases_run", []))
    profiles = ",".join(cov.get("profiles_run", []))
    callables = f"{cov.get('callables_exercised', 0)}/{cov.get('callables_total', 0)}"
    net = cov.get("network", "blocked")
    lines.append(f"  coverage: phases={phases} profiles={profiles} callables={callables} network={net}")
    return "\n".join(lines)
