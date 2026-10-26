"""Env-wrapper access patterns and attribution of toolchain reads."""
import json
from pathlib import Path

import pytest

from trustlens.contracts import ROOT, iter_jsonl, validate
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
BENCH = ROOT / "bench" / "packages"
bwrap_ok = check_env().get("bwrap_ok")


def _rows(result):
    rows = list(iter_jsonl(result["raw_events_path"]))
    for row in rows:
        validate("raw_event", row)
    validate("run_meta", json.loads(Path(result["run_meta_path"]).read_text()))
    return rows


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_env_access_patterns(tmp_path):
    result = run_package(
        str(DATA / "env_patterns"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=60,
    )
    rows = [row for row in _rows(result) if row["kind"] == "env.read" and row["attributed_to"] == "pkg"]
    names = {row["detail"]["name"] for row in rows}
    assert "AWS_SECRET_ACCESS_KEY" in names
    assert "GITHUB_TOKEN" in names
    assert "*" in names
    assert any("aws_secret_env" in row.get("canary_match", []) for row in rows if row["detail"]["name"] == "AWS_SECRET_ACCESS_KEY")
    assert any("github_token_env" in row.get("canary_match", []) for row in rows if row["detail"]["name"] == "GITHUB_TOKEN")
    assert all(row["evidence"].get("layer") == "env" for row in rows)


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_clean_slug_has_no_pkg_env_or_file_events(tmp_path):
    result = run_package(
        str(BENCH / "clean" / "clean_slug"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install", "import_all", "call_all"), timeout_s=90,
    )
    rows = _rows(result)
    noisy = [
        row for row in rows
        if row["attributed_to"] == "pkg" and row["kind"] in {"env.read", "file.read", "file.write", "file.new"}
    ]
    assert noisy == []


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_rest_wrapper_pkg_events_are_the_claimed_ones(tmp_path):
    result = run_package(
        str(BENCH / "clean" / "rest_wrapper"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("install", "call_all"), timeout_s=90,
    )
    rows = [row for row in _rows(result) if row["attributed_to"] == "pkg"]
    assert any(row["kind"] == "env.read" and row["detail"]["name"] == "API_TOKEN" for row in rows)
    assert any(row["kind"].startswith("net.") for row in rows)
    assert not any(row["kind"] in {"file.read", "file.write", "file.new"} for row in rows)
