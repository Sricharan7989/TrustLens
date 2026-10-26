"""dev vs ci camouflage: hostname gate and GITHUB_ACTIONS gate."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl, validate
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


def _net(rows, profile):
    return [row for row in rows if row["profile"] == profile and row["kind"].startswith("net.") and row["attributed_to"] == "pkg"]


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_hostname_gate_only_in_ci(tmp_path):
    result = run_package(
        str(DATA / "hostname_gate"), str(tmp_path), runner="live", profiles=("dev", "ci"),
        triggers=("call_all",), timeout_s=90,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    for row in rows:
        validate("raw_event", row)
    assert _net(rows, "ci")
    assert not _net(rows, "dev")
    assert {row["profile"] for row in rows} >= {"dev", "ci"}


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_github_actions_gate_only_in_ci(tmp_path):
    result = run_package(
        str(DATA / "github_gate"), str(tmp_path), runner="live", profiles=("dev", "ci"),
        triggers=("call_all",), timeout_s=90,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    assert _net(rows, "ci")
    assert not _net(rows, "dev")
    assert any(row["profile"] == "ci" and row["kind"] == "env.read" and row["detail"].get("name") == "GITHUB_ACTIONS" for row in rows)
