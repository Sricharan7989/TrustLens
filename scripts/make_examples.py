#!/usr/bin/env python3
"""Regenerate schemas/examples/<pkg>/{claims,fingerprint,verdict}.json from the recorded raw events. OWNER: Lead.
Run after a contract change: `make fixtures`. Raw events + run_meta are recorded live runs (see docs/CONTRACTS.md); do not hand-edit."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml  # noqa: E402

from trustlens.claims import extract_claims  # noqa: E402
from trustlens.contracts import EXAMPLES, validate  # noqa: E402
from trustlens.engine import evaluate  # noqa: E402
from trustlens.fingerprint import build_fingerprint  # noqa: E402

for p in yaml.safe_load((ROOT / "bench" / "labels.yaml").read_text())["packages"]:
    d = EXAMPLES / Path(p["path"]).name
    if not (d / "raw_events.jsonl").exists():
        continue
    meta = json.loads((d / "run_meta.json").read_text())
    claims = extract_claims(str(ROOT / p["path"]))
    claims["package"]["path"] = p["path"]
    fp = build_fingerprint(str(d / "raw_events.jsonl"), meta, claims["package"])
    verdict = evaluate(fp, claims)
    for kind, obj in (("claims", claims), ("fingerprint", fp), ("verdict", verdict)):
        validate(kind, obj)
        (d / f"{kind}.json").write_text(json.dumps(obj, indent=1) + "\n")
    print("examples:", d.name, verdict["verdict"])
