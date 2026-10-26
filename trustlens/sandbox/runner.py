"""Dev A: public entry point. Dispatches to the fixture replay runner or the live bwrap runner.

FROZEN SIGNATURE (docs/CONTRACTS.md 2.1). Keep it; change the internals freely.
"""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TypedDict

DEFAULT_TRIGGERS = ("install", "import_all", "call_all")  # A adds: fresh_startup, cli


class RunResult(TypedDict):
    raw_events_path: str   # JSONL, each line conforms to schemas/raw_event.schema.json
    run_meta_path: str     # JSON, conforms to schemas/run_meta.schema.json
    run_meta: dict


def run_package(
    pkg_path: str,
    out_dir: str,
    *,
    profiles: Sequence[str] = ("dev", "ci"),
    triggers: Sequence[str] = DEFAULT_TRIGGERS,
    offline: bool = True,
    timeout_s: int = 120,
    runner: str = "auto",
) -> RunResult:
    """Run `pkg_path` (source dir; later also .whl/.tar.gz/.zip) in the sandbox and write
    out_dir/raw_events.jsonl + out_dir/run_meta.json.

    runner: "fixture" (replay schemas/examples/<dirname>/), "live" (bwrap), "auto" (live if
    check_env() says bwrap works, else fixture, else an INCONCLUSIVE-shaped empty result).
    The network is ALWAYS blocked; `offline` only disables optional lookups.
    """
    from .env_check import check_env
    from .fixture_runner import run_fixture

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    if runner == "auto":
        runner = "live" if check_env().get("bwrap_ok") else "fixture"
    if runner == "fixture":
        return run_fixture(pkg_path, out_dir, profiles=profiles, triggers=triggers)
    if runner == "live":
        from .live_probe import run_live

        return run_live(pkg_path, out_dir, profiles=profiles, triggers=triggers, timeout_s=timeout_s)
    raise ValueError(f"unknown runner {runner!r}")
