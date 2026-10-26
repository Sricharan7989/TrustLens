"""Dev A: can this machine run the sandbox? (bwrap, user namespaces, strace, docker, venv)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _read(p: str) -> str | None:
    try:
        return Path(p).read_text().strip()
    except OSError:
        return None


def check_env() -> dict:
    bwrap = shutil.which("bwrap")
    strace = os.environ.get("TRUSTLENS_STRACE") or shutil.which("strace")
    res = {
        "bwrap": bwrap,
        "strace": strace,
        "docker": shutil.which("docker"),
        "unprivileged_userns_clone": _read("/proc/sys/kernel/unprivileged_userns_clone"),
        "apparmor_restrict_unprivileged_userns": _read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        "max_user_namespaces": _read("/proc/sys/user/max_user_namespaces"),
        "bwrap_ok": False,
        "notes": [],
    }
    if bwrap:
        try:
            r = subprocess.run(
                [bwrap, "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                 "--symlink", "usr/bin", "/bin", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--dev", "/dev",
                 "/usr/bin/true"], capture_output=True, timeout=15)
            res["bwrap_ok"] = r.returncode == 0
            if r.returncode:
                res["notes"].append("bwrap failed: " + r.stderr.decode(errors="replace")[:200])
        except Exception as e:  # noqa: BLE001
            res["notes"].append(f"bwrap error: {e}")
    else:
        res["notes"].append("bubblewrap not installed: sudo apt install bubblewrap")
    if res["apparmor_restrict_unprivileged_userns"] == "1" and not res["bwrap_ok"]:
        res["notes"].append("Ubuntu 23.10+/24.04 restricts userns: see scripts/check_env.sh for the sysctl/AppArmor fix or use Docker")
    if not strace:
        res["notes"].append("strace missing: second tracing layer disabled (sudo apt install strace)")
    return res


if __name__ == "__main__":
    import json

    out = check_env()
    print(json.dumps(out, indent=1))
    raise SystemExit(0 if out["bwrap_ok"] else 1)
