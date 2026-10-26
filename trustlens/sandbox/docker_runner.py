"""Docker fallback runner. Same agent and canary world as bwrap, with the network off.

`docker run --rm --network none --read-only --cap-drop ALL --tmpfs …` plus a writable
bind of the per-run work directory (the root filesystem stays read-only).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path


def docker_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        result = subprocess.run([docker, "info"], capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def pick_image() -> str:
    chosen = os.environ.get("TRUSTLENS_DOCKER_IMAGE")
    if chosen:
        return chosen
    docker = shutil.which("docker")
    if not docker:
        return "python:3.12-slim"
    try:
        result = subprocess.run([docker, "images", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return "python:3.12-slim"
    for line in result.stdout.splitlines():
        if "python" in line.lower() and "<none>" not in line:
            return line.strip()
    return "python:3.12-slim"


def docker_command(*, work: Path, image: str, hostname: str, env: dict[str, str], cwd: str, inner: list[str]) -> list[str]:
    """Host argv for one sandboxed command. No shell."""
    docker = shutil.which("docker") or "docker"
    cmd = [
        docker, "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--tmpfs", "/tmp:rw,nosuid,size=128m",
        "--tmpfs", "/run:rw,nosuid,size=32m",
        "-v", f"{work}:/w",
        "--hostname", hostname,
        "-w", cwd,
        "--user", "0:0",
    ]
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append(image)
    cmd.extend(inner)
    return cmd


def run_docker(
    pkg_path: str,
    out_dir: str,
    *,
    profiles: Sequence[str],
    triggers: Sequence[str],
    timeout_s: int = 120,
) -> dict:
    """Run `pkg_path` under Docker. Raises only when Docker itself is missing (bad environment, not package behaviour)."""
    if not docker_available():
        raise RuntimeError("docker is not available; install Docker or use runner=live/fixture")
    from .live_probe import run_live

    return run_live(
        pkg_path, out_dir, profiles=profiles, triggers=triggers, timeout_s=timeout_s, backend="docker",
    )
