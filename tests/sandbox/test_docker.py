"""Docker fallback argv, and a live run when a daemon is actually available."""
import shutil

import pytest

from trustlens.contracts import ROOT, iter_jsonl
from trustlens.sandbox.docker_runner import docker_available, docker_command
from trustlens.sandbox.runner import run_package

BENCH = ROOT / "bench" / "packages"


def test_docker_command_has_required_flags(tmp_path):
    argv = docker_command(
        work=tmp_path, image="python:3.12-slim", hostname="fv-az123-456",
        env={"HOME": "/w/home", "FP_PROFILE": "ci"}, cwd="/w/site", inner=["python3", "-c", "pass"],
    )
    assert argv[1:3] == ["run", "--rm"]
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--tmpfs" in argv
    assert "python:3.12-slim" in argv
    assert argv[-3:] == ["python3", "-c", "pass"]


@pytest.mark.skipif(not docker_available(), reason="docker daemon unavailable")
def test_docker_evil_slug_matches_canary(tmp_path):
    result = run_package(
        str(BENCH / "malicious" / "evil_slug"), str(tmp_path), runner="docker", profiles=("dev",),
        triggers=("install",), timeout_s=120,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    assert result["run_meta"]["run"]["sandbox"] == "docker"
    assert any(row.get("canary_match") for row in rows)
    assert shutil.which("docker")
