"""Real offline install, .pth startup hooks, and honest install failures."""
import json
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl, validate
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


def _events(result):
    rows = list(iter_jsonl(result["raw_events_path"]))
    for row in rows:
        validate("raw_event", row)
    validate("run_meta", json.loads(Path(result["run_meta_path"]).read_text()))
    return rows


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_pth_toy_install_and_fresh_startup(tmp_path):
    result = run_package(
        str(DATA / "pth_toy"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install", "fresh_startup"), timeout_s=90,
    )
    meta = result["run_meta"]
    assert meta["coverage"]["install_completed"] is True
    assert meta["coverage"]["install_note"] in (None, "")
    rows = _events(result)
    assert any(row["kind"] == "startup.pth" and "import _zz_helper" in row["detail"].get("line_text", "") for row in rows)
    assert any(row["kind"] == "install.hook" and row["detail"].get("cmd") == "cmdclass" for row in rows)
    assert any(row["kind"] == "file.new" and "_zz_helper.py" in row["detail"].get("path", "") for row in rows)
    startup = [row for row in rows if row["phase"] == "startup" and row["trigger"] == "fresh_startup"]
    assert any(row["kind"] == "file.read" and "ssh_key" in row.get("canary_match", []) for row in startup)
    assert any(row["kind"].startswith("net.") for row in startup)
    assert all(row["outcome"] in {"blocked", "attempted"} for row in startup if row["kind"].startswith("net."))


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_broken_install_is_run_error_not_silent(tmp_path):
    result = run_package(
        str(DATA / "broken_install"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install",), timeout_s=40,
    )
    meta = result["run_meta"]["coverage"]
    assert meta["install_completed"] is False
    assert meta["install_note"]
    rows = _events(result)
    assert any(row["kind"] == "run.error" and row["detail"]["where"] == "install" for row in rows)
    assert any("real pip install did not complete" in note for note in meta["not_observed"])


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_install_timeout_is_run_error(tmp_path):
    result = run_package(
        str(DATA / "hang_install"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install",), timeout_s=5,
    )
    meta = result["run_meta"]["coverage"]
    assert meta["install_completed"] is False
    rows = _events(result)
    assert any(row["kind"] == "run.error" and "timeout" in row["detail"].get("message", "") for row in rows)
