"""Dev D: SARIF 2.1.0 exporter for CI integration (e.g. GitHub Code Scanning).
Conforms to OASIS SARIF v2.1.0. Completely offline, deterministic.
"""
from __future__ import annotations

import json


def render_sarif(verdict: dict, fingerprint: dict | None = None, claims: dict | None = None) -> str:
    """Generate SARIF 2.1.0 JSON representation from verdict findings."""
    pkg = verdict.get("package", {})
    findings = verdict.get("findings") or []

    # Map findings severities to SARIF levels
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    rules_dict = {}
    results = []

    for f in findings:
        rule_id = f.get("rule", "TL000")
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.get("title", rule_id),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("explanation", "")},
                "defaultConfiguration": {
                    "level": level_map.get(f.get("severity", "medium").lower(), "warning")
                },
                "properties": {
                    "capability": f.get("capability"),
                    "signal_class": f.get("signal_class"),
                    "canary_hit": f.get("canary_hit", False),
                    "env_differential": f.get("env_differential", False),
                },
            }

        locations = []
        for ev in f.get("evidence") or []:
            fpath = ev.get("file")
            line = ev.get("line") or 1
            if fpath:
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(fpath).replace("\\", "/")},
                            "region": {"startLine": int(line)},
                        }
                    }
                )

        if not locations and pkg.get("path"):
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(pkg["path"]).replace("\\", "/")},
                        "region": {"startLine": 1},
                    }
                }
            )

        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(f.get("severity", "medium").lower(), "warning"),
                "message": {
                    "text": f"{f.get('title')}: {f.get('explanation')}"
                },
                "locations": locations,
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TrustLens AI",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/iota-x-enigma/trustlens",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_data, indent=2)
