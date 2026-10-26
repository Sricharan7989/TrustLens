"""Dev A. Add live-sandbox tests here; they must skip cleanly when bwrap is unavailable."""
import json
from pathlib import Path

import pytest

from trustlens.contracts import ROOT, iter_jsonl, validate
from trustlens.sandbox import check_env, run_package

BENCH = ROOT / "bench" / "packages"
bwrap_ok = check_env().get("bwrap_ok")


def test_check_env_shape():
    env = check_env()
    assert "bwrap_ok" in env and "notes" in env


def test_fixture_runner_replays_and_marks_stub(tmp_path):
    r = run_package(str(BENCH / "malicious/evil_slug"), str(tmp_path), runner="fixture")
    assert r["run_meta"]["run"]["stub"] is True and r["run_meta"]["run"]["sandbox"] == "fixture"
    validate("run_meta", json.loads(Path(r["run_meta_path"]).read_text()))
    assert any(e["canary_match"] for e in iter_jsonl(r["raw_events_path"]))


def test_unknown_package_fixture_is_inconclusive_not_clean(tmp_path):
    p = tmp_path / "pkg"
    p.mkdir()
    r = run_package(str(p), str(tmp_path / "out"), runner="fixture")
    assert r["run_meta"]["coverage"]["install_completed"] is False


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_live_evil_slug_has_canary_read_and_blocked_net(tmp_path):
    r = run_package(str(BENCH / "malicious/evil_slug"), str(tmp_path), runner="live", profiles=("dev",), timeout_s=90)
    evs = list(iter_jsonl(r["raw_events_path"]))
    for e in evs:
        validate("raw_event", e)
    assert any(e["canary_match"] for e in evs), "canary read must be matched"
    assert all(e["outcome"] in ("blocked", "attempted") for e in evs if e["kind"].startswith("net."))


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_live_delayed_slug_is_env_differential(tmp_path):
    r = run_package(str(BENCH / "malicious/delayed_slug"), str(tmp_path), runner="live", profiles=("dev", "ci"), timeout_s=120)
    ev = list(iter_jsonl(r["raw_events_path"]))
    assert any(e["profile"] == "ci" and e["kind"].startswith(("net.", "dyn.")) for e in ev)
    assert not any(e["profile"] == "dev" and e["kind"].startswith("net.") for e in ev)
