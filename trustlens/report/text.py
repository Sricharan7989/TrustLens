"""Dev D: terminal + JSON renderers."""
from __future__ import annotations

import json

COLORS = {"PASS": "\033[32m", "REVIEW": "\033[33m", "BLOCK": "\033[31m"}


def render_json(verdict: dict, fingerprint: dict | None = None, claims: dict | None = None) -> str:
    return json.dumps({"verdict": verdict, "claims": claims, "fingerprint": fingerprint}, indent=1)


def render_text(verdict: dict, color: bool = False) -> str:
    c, r = (COLORS.get(verdict["action"], ""), "\033[0m") if color else ("", "")
    p = verdict["package"]
    lines = [f'{c}{verdict["action"]:6} {verdict["verdict"]}{r}  {p["name"]} {p["version"]}  (score {verdict["score"]}, confidence {verdict["confidence"]})', "  " + verdict["summary"]]
    for f in verdict["findings"][:6]:
        lines.append(f'  - [{f["severity"]}] {f["title"]}')
        lines.append(f'      {f["explanation"][:240]}')
    cov = verdict["coverage"]
    lines.append(f'  coverage: phases={",".join(cov["phases_run"])} profiles={",".join(cov["profiles_run"])} callables={cov["callables_exercised"]}/{cov["callables_total"]} network={cov["network"]}')
    return "\n".join(lines)
