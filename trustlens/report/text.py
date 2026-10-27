"""Dev D: terminal + JSON renderers."""
from __future__ import annotations

import json
import re

COLORS = {"PASS": "\033[32m", "REVIEW": "\033[33m", "BLOCK": "\033[31m"}

# Regex for stripping ESC/CSI/C1 controls and non-printable control characters except \t, \n, \r
_CONTROL_RE = re.compile(
    r"\x1b\[[0-9;]*[a-zA-Z]|\x9b\[[0-9;]*[a-zA-Z]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)
_TAG_RE = re.compile(r"<[^>]+>")
_CANARY_RE = re.compile(r"TLCANARY[A-Za-z0-9]+")


def strip_controls(s: str) -> str:
    """Remove ESC/CSI/C1 and control characters (\x00-\x1f except \t \n \r), plus HTML tags."""
    if not isinstance(s, str):
        s = str(s)
    cleaned = _CONTROL_RE.sub("", s)
    return _TAG_RE.sub("", cleaned)


def redact_canaries(s: str) -> str:
    """Redact canary token bytes (replace TLCANARY... with [canary])."""
    if not isinstance(s, str):
        s = str(s)
    return _CANARY_RE.sub("[canary]", s)


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

    pkg_name = strip_controls(redact_canaries(p.get("name", "")))
    pkg_ver = strip_controls(redact_canaries(p.get("version", "")))
    summary = strip_controls(redact_canaries(verdict.get("summary", "")))

    action = verdict.get("action", "")
    verd = verdict.get("verdict", "")
    score = verdict.get("score", 0)
    conf = verdict.get("confidence", "")

    lines = [
        f"{c}{action:6} {verd}{r}  {pkg_name} {pkg_ver}  (score {score}, confidence {conf})",
        "  " + summary,
    ]
    for f in (verdict.get("findings") or [])[:6]:
        title = strip_controls(redact_canaries(f.get("title", "")))
        expl = strip_controls(redact_canaries(f.get("explanation", "")))
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
