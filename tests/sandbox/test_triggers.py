"""Trigger matrix: typed calls, classes, and console-script CLI entry points."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl, validate
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_call_matrix_exercises_typed_and_methods(tmp_path):
    result = run_package(
        str(DATA / "call_matrix"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=60,
    )
    cov = result["run_meta"]["coverage"]
    assert cov["callables_total"] >= 3
    assert cov["callables_exercised"] >= 3
    names = {row["detail"].get("name") for row in iter_jsonl(result["raw_events_path"]) if row["kind"] == "env.read"}
    assert "TL_TYPED_MATRIX" in names
    assert "TL_METHOD_MATRIX" in names
    assert "TL_MAIN_MATRIX" in names


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_cli_entry_point_is_triggered(tmp_path):
    result = run_package(
        str(DATA / "cli_toy"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install", "cli"), timeout_s=90,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    for row in rows:
        validate("raw_event", row)
    cli = [row for row in rows if str(row["trigger"]).startswith("cli:")]
    assert cli
    assert any(row["phase"] == "cli" and row["kind"] == "file.read" and "ssh_key" in row.get("canary_match", []) for row in cli)
    assert any(row["phase"] == "cli" and row["kind"].startswith("net.") for row in cli)
    assert result["run_meta"]["coverage"]["install_completed"] is True
