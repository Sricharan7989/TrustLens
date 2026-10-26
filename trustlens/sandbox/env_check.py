"""Dev A: can this machine run the sandbox? (bwrap, user namespaces, strace, docker, venv)."""
from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

_BWRAP_BIND = [
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--symlink", "usr/bin", "/bin",
    "--proc", "/proc",
    "--dev", "/dev",
]


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _libfaketime() -> str | None:
    roots = (
        "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib64/faketime/libfaketime.so.1",
        "/usr/lib/faketime/libfaketime.so.1",
    )
    for path in roots:
        if Path(path).is_file():
            return path
    return None


def _venv_ok() -> bool:
    try:
        result = subprocess.run(["python3", "-c", "import venv, ensurepip"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _bwrap_ok_process(bwrap: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [bwrap, *_BWRAP_BIND, "--unshare-net", "--unshare-pid", "/usr/bin/true"],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"bwrap error: {exc}"
    if result.returncode != 0:
        err = result.stderr.decode(errors="replace")[:200]
        return False, "bwrap failed: " + err
    return True, ""


def _network_blocked(bwrap: str) -> bool:
    """True only when a connect to a public address fails inside a fresh netns."""
    probe = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(1)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 80)); sys.exit(1)\n"
        "except OSError:\n"
        "    sys.exit(0)\n"
    )
    try:
        result = subprocess.run(
            [bwrap, *_BWRAP_BIND, "--unshare-net", "/usr/bin/python3", "-c", probe],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _strace_in_bwrap(bwrap: str, strace: str) -> bool:
    try:
        result = subprocess.run(
            [bwrap, *_BWRAP_BIND, "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid", "--die-with-parent",
             strace, "-e", "trace=execve", "-o", "/tmp/tl-strace-probe.txt", "/usr/bin/true"],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _docker_ok(docker: str | None) -> bool:
    if not docker:
        return False
    try:
        result = subprocess.run([docker, "info"], capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@lru_cache(maxsize=1)
def check_env() -> dict:
    """Report whether a live sandbox is safe to use. `bwrap_ok` is true only when rootless bwrap works and the network probe is blocked."""
    bwrap = shutil.which("bwrap")
    strace = os.environ.get("TRUSTLENS_STRACE") or shutil.which("strace")
    docker = shutil.which("docker")
    faketime = _libfaketime()
    res: dict = {
        "bwrap": bwrap,
        "strace": strace,
        "docker": docker,
        "unprivileged_userns_clone": _read("/proc/sys/kernel/unprivileged_userns_clone"),
        "apparmor_restrict_unprivileged_userns": _read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        "max_user_namespaces": _read("/proc/sys/user/max_user_namespaces"),
        "bwrap_ok": False,
        "network_blocked": False,
        "strace_in_bwrap": False,
        "docker_ok": False,
        "venv_ok": _venv_ok(),
        "libfaketime": faketime,
        "live_safe": False,
        "notes": [],
    }
    if not res["venv_ok"]:
        res["notes"].append("python3-venv missing: sudo apt install python3-venv (host tooling; the sandbox itself does not need it)")
    if not bwrap:
        res["notes"].append("bubblewrap not installed: sudo apt install bubblewrap")
    else:
        runs, detail = _bwrap_ok_process(bwrap)
        if not runs:
            res["notes"].append(detail)
        else:
            res["network_blocked"] = _network_blocked(bwrap)
            if not res["network_blocked"]:
                res["notes"].append("bwrap started but a connect to 1.1.1.1:80 succeeded; network is NOT blocked — do not run samples")
            if strace:
                res["strace_in_bwrap"] = _strace_in_bwrap(bwrap, strace)
                if not res["strace_in_bwrap"]:
                    res["notes"].append("strace is installed but failed inside bwrap; the native-code layer stays off")
        res["bwrap_ok"] = bool(runs and res["network_blocked"])
    if res["apparmor_restrict_unprivileged_userns"] == "1" and not res["bwrap_ok"]:
        res["notes"].append(
            "Ubuntu 23.10+/24.04 restricts unprivileged user namespaces. "
            "See scripts/check_env.sh: sysctl kernel.apparmor_restrict_unprivileged_userns=0, an AppArmor profile for bwrap, or runner=docker"
        )
    if not strace:
        res["notes"].append("strace missing: second tracing layer disabled (sudo apt install strace)")
    res["docker_ok"] = _docker_ok(docker)
    if not docker:
        res["notes"].append("docker absent (optional fallback runner)")
    elif not res["docker_ok"]:
        res["notes"].append("docker binary found but `docker info` failed; runner=docker will not work")
    if not faketime:
        res["notes"].append("libfaketime not found: clock+30d patches time.time/datetime in Python only (C-level time is not shifted)")
    res["live_safe"] = bool(res["bwrap_ok"])
    return res


if __name__ == "__main__":
    import json

    out = check_env()
    print(json.dumps(out, indent=1))
    raise SystemExit(0 if out["live_safe"] else 1)
