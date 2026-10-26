"""Dev A: replays recorded raw events from schemas/examples/<package-dir-name>/ (no sandbox needed).

Used by `make demo` so the whole pipeline runs on any laptop from hour 0.
"""
from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path

from trustlens.contracts import EXAMPLES


def run_fixture(pkg_path: str, out_dir: str, *, profiles: Sequence[str], triggers: Sequence[str]) -> dict:
    name = Path(pkg_path).resolve().name
    src = EXAMPLES / name
    out = Path(out_dir)
    raw_out, meta_out = out / "raw_events.jsonl", out / "run_meta.json"
    if (src / "raw_events.jsonl").exists():
        shutil.copy(src / "raw_events.jsonl", raw_out)
        meta = json.loads((src / "run_meta.json").read_text())
        meta["run"].update(sandbox="fixture", stub=True)  # recorded live run replayed: say so honestly
    else:  # nothing recorded and no live sandbox: be honest -> engine will say INCONCLUSIVE
        raw_out.write_text("")
        meta = {
            "run": {"sandbox": "none", "network": "blocked", "canaries": [], "phases": [], "profiles": [], "variants": [], "stub": True},
            "coverage": {"phases_run": [], "profiles_run": [], "triggers_run": [], "install_completed": False,
                         "install_note": "no fixture and no live sandbox", "network": "blocked",
                         "callables_total": 0, "callables_exercised": 0,
                         "not_observed": ["everything: package was not executed"]},
            "canaries": [],
        }
    meta_out.write_text(json.dumps(meta, indent=1))
    return {"raw_events_path": str(raw_out), "run_meta_path": str(meta_out), "run_meta": meta}
