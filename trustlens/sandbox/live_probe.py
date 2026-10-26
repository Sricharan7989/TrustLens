"""Dev A: v0 LIVE runner (ported from ps1_poc_sandbox_probe). Rootless bwrap, network unshared, canary world.

Phases (v0): install (setup.py egg_info, no network) -> import_all -> call_all, for each profile (dev, ci).
TODO(Dev A, see prompts/PROMPT_DEV_A.md): real offline pip install into venv + site-packages diff, fresh-interpreter
startup, strace layer, clock+30d variant, CLI entry points, chain-loading sitecustomize, timeouts per phase.
SAFETY: only ever pass untrusted packages through this runner; never run them on the host.
"""
from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent / "agent"
PHASE_OF = {"install": "install", "import_all": "import", "call_all": "call"}
PHASE_ORDER = {"install": 0, "startup": 1, "import": 2, "call": 3, "cli": 4}

CANARY_DEFS = [
    {"id": "ssh_key", "kind": "file", "where": ".ssh/id_rsa", "body": "-----BEGIN OPENSSH PRIVATE KEY-----\n{tok}\n-----END OPENSSH PRIVATE KEY-----\n"},
    {"id": "aws_creds", "kind": "file", "where": ".aws/credentials", "body": "[default]\naws_access_key_id = AKIA{tok}\naws_secret_access_key = {tok}\n"},
    {"id": "npmrc", "kind": "file", "where": ".npmrc", "body": "//registry.npmjs.org/:_authToken={tok}\n"},
    {"id": "aws_secret_env", "kind": "env", "where": "AWS_SECRET_ACCESS_KEY", "body": "{tok}"},
    {"id": "github_token_env", "kind": "env", "where": "GITHUB_TOKEN", "body": "{tok}"},
]


def _world(profile: str, work: Path) -> tuple[dict, dict]:
    """Build fake HOME with canaries + profile camouflage. Returns (canary manifest, extra env)."""
    home = work / "home"
    home.mkdir(parents=True)
    cans, env = [], {}
    for d in CANARY_DEFS:
        tok = "TLCANARY" + d["id"].upper().replace("_", "") + secrets.token_hex(6)
        c = {"id": d["id"], "kind": d["kind"], "where": d["where"], "token": tok}
        cans.append(c)
        if d["kind"] == "file":
            f = home / d["where"]
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(d["body"].format(tok=tok))
        else:
            env[d["where"]] = d["body"].format(tok=tok)
    if profile == "dev":  # developer-laptop camouflage (gap #1)
        (home / ".bash_history").write_text("\n".join(f"git status # {i}" for i in range(200)) + "\n")
        (home / ".gitconfig").write_text("[user]\n\tname = Ravi\n\temail = ravi@example.com\n")
        (home / ".ssh" / "known_hosts").write_text("github.com ssh-ed25519 AAAAC3Nza\n")
        for sub in ("Desktop", "Downloads", "Documents"):
            (home / sub).mkdir()
            for i in range(4):
                (home / sub / f"file{i}.txt").write_text("x")
        env.update({"USER": "ravi", "LOGNAME": "ravi", "SHELL": "/bin/bash", "LANG": "en_US.UTF-8", "DISPLAY": ":0"})
    else:  # ci
        env.update({"CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "USER": "runner"})
    return {"canaries": cans}, env


def _snapshot(home: Path) -> dict:
    snap = {}
    for p in home.rglob("*"):
        if p.is_file():
            try:
                snap[str(p.relative_to(home))] = p.stat().st_mtime_ns, p.stat().st_size
            except OSError:
                pass
    return snap


def run_live(pkg_path: str, out_dir: str, *, profiles: Sequence[str], triggers: Sequence[str], timeout_s: int = 120) -> dict:
    t0 = time.time()
    pkg = Path(pkg_path).resolve()
    out = Path(out_dir)
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bwrap not found; run scripts/check_env.sh")
    events: list[dict] = []
    coverage_phases, ran_triggers, cov_tot, cov_ex, failed_mods = set(), [], 0, 0, []
    install_ok, install_note, canaries_out = True, None, []
    # setuptools is copied into the world so `setup.py egg_info` works offline (system python has none)
    st_src = None
    try:
        import setuptools  # type: ignore

        st_src = Path(setuptools.__file__).parent
    except Exception:  # noqa: BLE001
        install_ok, install_note = False, "setuptools missing on host venv (pip install -r requirements.txt)"
    for profile in profiles:
        work = Path(tempfile.mkdtemp(prefix=f"tl-{profile}-"))
        manifest, penv = _world(profile, work)
        canaries_out = manifest["canaries"]
        (work / "canaries.json").write_text(json.dumps(manifest))
        tools = work / "tools"
        tools.mkdir()
        if st_src:
            for name in ("setuptools", "_distutils_hack", "packaging", "wheel"):
                for src in list(st_src.parent.glob(name)) + list(st_src.parent.glob(name + "-*.dist-info")):
                    shutil.copytree(src, tools / src.name, ignore=shutil.ignore_patterns("__pycache__"))
        site = work / "site"
        shutil.copytree(pkg, site, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        shutil.copytree(AGENT_DIR, work / "agent")
        log, covf = work / "fp.jsonl", work / "cov.jsonl"
        log.touch()
        covf.touch()
        hostname = "ravi-laptop" if profile == "dev" else "fv-az123-456"
        base = [bwrap, "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", str(work), "/w", "--unshare-net", "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--hostname", hostname,
                "--die-with-parent", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/w/home",
                "--setenv", "FP_LOG", "/w/fp.jsonl", "--setenv", "FP_COV", "/w/cov.jsonl", "--setenv", "FP_CANARIES", "/w/canaries.json",
                "--setenv", "FP_PROFILE", profile, "--setenv", "FP_PKG_DIRS", "/w/site", "--setenv", "FP_TOOL_DIRS", "/w/tools:/w/agent", "--setenv", "FP_IGNORE", "/w/fp.jsonl:/w/cov.jsonl:/w/canaries.json",
                "--setenv", "PYTHONDONTWRITEBYTECODE", "1"]
        for k, v in penv.items():
            base += ["--setenv", k, v]

        def phase(trigger: str, argv: list[str], cwd: str, pypath: str, extra_env: dict | None = None):
            cmd = base + ["--setenv", "FP_PHASE", PHASE_OF.get(trigger, "import"), "--setenv", "FP_TRIGGER", trigger,  # noqa: B023 (closure only called inside the same loop iteration)
                          "--setenv", "PYTHONPATH", pypath, "--chdir", cwd]
            for k, v in (extra_env or {}).items():
                cmd += ["--setenv", k, v]
            ran_triggers.append(trigger)
            coverage_phases.add(PHASE_OF.get(trigger, "import"))
            try:
                return subprocess.run(cmd + argv, capture_output=True, timeout=timeout_s)
            except subprocess.TimeoutExpired:
                events.append({"seq": 0, "phase": PHASE_OF.get(trigger, "import"), "trigger": trigger, "profile": profile, "variant": "default",  # noqa: B023
                               "kind": "run.error", "detail": {"where": trigger, "message": "timeout"}, "outcome": "unknown", "attributed_to": "toolchain"})
                return None

        before = _snapshot(work / "home")
        if "install" in triggers:
            r = phase("install", ["/usr/bin/python3", "setup.py", "-q", "egg_info", "--egg-base", "/w"] if (pkg / "setup.py").exists() else ["/usr/bin/true"],
                      "/w/site", "/w/tools:/w/agent")
            if r is not None and r.returncode != 0 and (pkg / "setup.py").exists():
                install_note = (install_note or "") + f"[{profile}] setup.py egg_info exit {r.returncode}"
        if "import_all" in triggers:
            phase("import_all", ["/usr/bin/python3", "/w/agent/harness.py", "import"], "/w/site", "/w/agent:/w/site")
        if "call_all" in triggers:
            phase("call_all", ["/usr/bin/python3", "/w/agent/harness.py", "call"], "/w/site", "/w/agent:/w/site")
        after = _snapshot(work / "home")
        for rel, meta in after.items():  # HOME diff: files created/changed by the package (persistence, droppers)
            if before.get(rel) != meta:
                events.append({"seq": 0, "phase": "call", "trigger": "home_diff", "profile": profile, "variant": "default", "kind": "file.write",
                               "detail": {"path": "~/" + rel, "mode": "diff"}, "outcome": "succeeded", "attributed_to": "pkg",
                               "evidence": {"layer": "fs_diff", "file": None, "line": None}, "canary_match": []})
        for line in log.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        for line in covf.read_text().splitlines():
            c = json.loads(line)
            if c["callables_total"] or c["modules"]:
                cov_tot = max(cov_tot, c["callables_total"]) if profile == profiles[0] else cov_tot
                cov_ex = max(cov_ex, c["callables_exercised"]) if profile == profiles[0] else cov_ex
            failed_mods += c["modules_failed"]
        shutil.rmtree(work, ignore_errors=True)

    events.sort(key=lambda e: (list(profiles).index(e["profile"]) if e["profile"] in profiles else 9, PHASE_ORDER.get(e["phase"], 9), e.get("t") or 0, e.get("seq", 0)))
    raw = out / "raw_events.jsonl"
    with open(raw, "w") as fh:
        for i, e in enumerate(events):
            e["seq"] = i
            fh.write(json.dumps(e) + "\n")
    not_obs = ["real `pip install` (wheel/.pth/sitecustomize) not exercised (v0 uses setup.py egg_info)", "fresh-interpreter startup not tested",
               "clock+30d variant not run", "CLI entry points not run", "strace layer not active (native code is invisible)"]
    meta = {
        "run": {"sandbox": "bwrap", "network": "blocked", "canaries": [c["id"] for c in canaries_out], "phases": sorted(coverage_phases, key=PHASE_ORDER.get),
                "profiles": list(profiles), "variants": ["default"], "started_at": datetime.fromtimestamp(t0, UTC).isoformat(),
                "duration_s": round(time.time() - t0, 2), "stub": False},
        "coverage": {"phases_run": sorted(coverage_phases, key=PHASE_ORDER.get), "profiles_run": list(profiles), "variants_run": ["default"],
                     "triggers_run": sorted(set(ran_triggers)), "install_completed": install_ok and "exit" not in (install_note or ""), "install_note": install_note,
                     "network": "blocked", "callables_total": cov_tot, "callables_exercised": cov_ex, "native_skipped": [], "strace_layer": False,
                     "not_observed": not_obs + ([f"modules failed to import: {', '.join(sorted(set(failed_mods))[:5])}"] if failed_mods else [])},
        "canaries": canaries_out,
    }
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1))
    return {"raw_events_path": str(raw), "run_meta_path": str(out / "run_meta.json"), "run_meta": meta}
