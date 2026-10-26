"""Sandbox-probe observations use the frozen file.read and env.read kinds."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_probe_toy_logs_watch_checks(tmp_path):
    result = run_package(
        str(DATA / "probe_toy"), str(tmp_path), runner="live", profiles=("dev", "ci"),
        triggers=("call_all",), timeout_s=60,
    )
    rows = [row for row in iter_jsonl(result["raw_events_path"]) if row["attributed_to"] == "pkg"]
    paths = {row["detail"].get("path") for row in rows if row["kind"] == "file.read"}
    assert any(path and path.endswith("/.dockerenv") for path in paths)
    assert any(path and path.endswith("/proc/1/cgroup") for path in paths)
    assert any(path and path.endswith("/proc/uptime") for path in paths)
    assert any(path and path.endswith("/proc/cpuinfo") for path in paths)
    names = {row["detail"].get("name") for row in rows if row["kind"] == "env.read"}
    assert "DISPLAY" in names
    assert "CI" in names
    assert "HOSTNAME" in names
    assert "NUMBER_OF_PROCESSORS" in names
    # dev has DISPLAY and no CI; ci has CI and no DISPLAY. Both reads are attempted or succeeded.
    assert any(row["profile"] == "dev" and row["detail"].get("name") == "DISPLAY" and row["outcome"] == "succeeded" for row in rows)
    assert any(row["profile"] == "ci" and row["detail"].get("name") == "CI" and row["outcome"] == "succeeded" for row in rows)
