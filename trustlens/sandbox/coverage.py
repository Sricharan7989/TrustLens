"""Honest coverage.not_observed text for a live run. Lists only gaps that apply to this run."""
from __future__ import annotations


def build_not_observed(
    *,
    triggers: list[str],
    ran_triggers: list[str],
    variants: list[str],
    strace_layer: bool,
    sinkhole: bool,
    clock_python_only: bool,
    install_completed: bool,
    install_requested: bool,
    cli_found: bool,
    failed_mods: list[str],
    extra: list[str] | None = None,
) -> list[str]:
    notes: list[str] = []
    ran = set(ran_triggers)
    wanted = set(triggers)
    if "fresh_startup" not in ran:
        notes.append("fresh-interpreter startup not tested")
    if "clock+30d" not in variants:
        notes.append("clock variant not run")
    elif clock_python_only:
        notes.append("clock shift is Python-level only; C-level time is not shifted")
    if not strace_layer:
        notes.append("strace layer not active (native code is invisible)")
    if not sinkhole:
        notes.append("loopback sinkhole not active")
    cli_ran = any(item == "cli" or item.startswith("cli:") for item in ran)
    if "cli" in wanted and not cli_found:
        notes.append("no console-script entry points to run")
    elif not cli_ran:
        notes.append("CLI entry points not run")
    if install_requested and not install_completed:
        notes.append("real pip install did not complete")
    if failed_mods:
        shown = ", ".join(sorted(set(failed_mods))[:5])
        notes.append(f"modules failed to import: {shown}")
    for item in extra or []:
        if item and item not in notes:
            notes.append(item)
    return notes
