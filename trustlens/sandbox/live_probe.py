"""Dev A: live sandbox runner. Rootless bwrap (or Docker), network unshared, canary world.

Phases: real offline pip install, fresh-interpreter startup, import, call, CLI.
Each selected trigger runs once per profile (dev, ci). Call and CLI also run as variant clock+30d.
Package code never executes on the host. Timeouts and install failures become run.error events.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from .coverage import build_not_observed
from .docker_runner import docker_command, pick_image
from .env_check import check_env
from .install_diff import diff_installed
from .strace_parse import baseline_keys, parse_strace

AGENT_DIR = Path(__file__).resolve().parent / "agent"
PY_BWRAP = "/usr/bin/python3"
PHASE_OF = {"install": "install", "fresh_startup": "startup", "import_all": "import", "call_all": "call", "cli": "cli"}
PHASE_ORDER = {"install": 0, "startup": 1, "import": 2, "call": 3, "cli": 4}
CANARY_DEFS = [
    {"id": "ssh_key", "kind": "file", "where": ".ssh/id_rsa",
     "body": "-----BEGIN OPENSSH PRIVATE KEY-----\n{tok}\n-----END OPENSSH PRIVATE KEY-----\n"},
    {"id": "aws_creds", "kind": "file", "where": ".aws/credentials",
     "body": "[default]\naws_access_key_id = AKIA{tok}\naws_secret_access_key = {tok}\n"},
    {"id": "npmrc", "kind": "file", "where": ".npmrc", "body": "//registry.npmjs.org/:_authToken={tok}\n"},
    {"id": "gcloud_creds", "kind": "file", "where": ".config/gcloud/application_default_credentials.json",
     "body": '{{"type": "authorized_user", "client_secret": "{tok}"}}\n'},
    {"id": "docker_config", "kind": "file", "where": ".docker/config.json",
     "body": '{{"auths": {{"https://index.docker.io/v1/": {{"auth": "{tok}"}}}}}}\n'},
    {"id": "aws_secret_env", "kind": "env", "where": "AWS_SECRET_ACCESS_KEY", "body": "{tok}"},
    {"id": "github_token_env", "kind": "env", "where": "GITHUB_TOKEN", "body": "{tok}"},
]
_TOOL_NAMES = ("pip", "setuptools", "pkg_resources", "_distutils_hack", "wheel", "packaging")


def _mint_canaries() -> list[dict]:
    import secrets
    minted = []
    for spec in CANARY_DEFS:
        token = "TLCANARY" + spec["id"].upper().replace("_", "") + secrets.token_hex(6)
        minted.append({**spec, "token": token})
    return minted


def _public_canaries(canaries: list[dict]) -> list[dict]:
    return [{"id": c["id"], "kind": c["kind"], "where": c["where"], "token": c["token"]} for c in canaries]


def _toolchain_source() -> Path | None:
    try:
        out = subprocess.check_output(
            [PY_BWRAP, "-c", "import setuptools, pathlib; print(pathlib.Path(setuptools.__file__).resolve().parent.parent)"],
            text=True, timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    path = Path(out.strip())
    return path if path.is_dir() else None


def _copy_toolchain(dest: Path) -> bool:
    src = _toolchain_source()
    if src is None:
        return False
    dest.mkdir(parents=True, exist_ok=True)
    for name in _TOOL_NAMES:
        for item in list(src.glob(name)) + list(src.glob(name + "-*.dist-info")) + list(src.glob(name + "-*.egg-info")):
            target = dest / item.name
            if item.is_dir():
                shutil.copytree(item, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"), dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)
    return (dest / "pip").is_dir() and (dest / "setuptools").is_dir()


def _stage_package(pkg: Path, work: Path) -> str:
    if pkg.is_file() and pkg.suffix == ".whl":
        shutil.copy2(pkg, work / "incoming.whl")
        return "/w/incoming.whl"
    site = work / "site"
    shutil.copytree(pkg, site, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    return "/w/site"


def _build_world(profile: str, work: Path, canaries: list[dict]) -> dict[str, str]:
    home = work / "home"
    home.mkdir(parents=True, exist_ok=True)
    env: dict[str, str] = {}
    for canary in canaries:
        if canary["kind"] == "file":
            dest = home / canary["where"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(canary["body"].format(tok=canary["token"]), encoding="utf-8")
        else:
            env[canary["where"]] = canary["body"].format(tok=canary["token"])
    if profile == "dev":
        (home / ".bash_history").write_text("\n".join(f"git status # {i}" for i in range(40)) + "\n", encoding="utf-8")
        (home / ".gitconfig").write_text("[user]\n\tname = Ravi\n\temail = ravi@example.com\n", encoding="utf-8")
        (home / ".ssh" / "known_hosts").write_text("github.com ssh-ed25519 AAAAC3Nza\n", encoding="utf-8")
        for sub in ("Desktop", "Downloads", "Documents", "work"):
            (home / sub).mkdir(exist_ok=True)
        env.update({"USER": "ravi", "LOGNAME": "ravi", "SHELL": "/bin/bash", "LANG": "en_US.UTF-8", "DISPLAY": ":0"})
    else:
        env.update({
            "CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "JENKINS_URL": "http://jenkins.invalid/job/demo",
            "USER": "runner", "LOGNAME": "runner", "SHELL": "/bin/bash", "LANG": "C.UTF-8",
        })
        workspace = work / "github" / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (work / "dockerenv").write_text("docker\n", encoding="utf-8")
    etc = work / "fake-etc"
    etc.mkdir(exist_ok=True)
    (etc / "hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="utf-8")
    (etc / "resolv.conf").write_text("nameserver 127.0.0.1\n", encoding="utf-8")
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n", encoding="utf-8")
    (work / "canaries.json").write_text(json.dumps({"canaries": _public_canaries(canaries)}), encoding="utf-8")
    return env


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    snap: dict[str, tuple[int, int]] = {}
    if not root.exists():
        return snap
    for path in root.rglob("*"):
        if path.is_file():
            try:
                stat = path.stat()
                snap[str(path.relative_to(root))] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                pass
    return snap


def _home_diff_events(before: dict, after: dict, *, phase: str, trigger: str, profile: str, variant: str) -> list[dict]:
    events = []
    now = time.time()
    for rel, meta in sorted(after.items()):
        if before.get(rel) == meta:
            continue
        events.append({
            "seq": 0, "t": now, "phase": phase, "trigger": trigger, "profile": profile, "variant": variant,
            "kind": "file.write", "detail": {"path": "~/" + rel, "mode": "diff"}, "outcome": "succeeded",
            "attributed_to": "pkg", "canary_match": [],
            "evidence": {"layer": "fs_diff", "file": None, "line": None},
        })
    return events


def _run_error(where: str, message: str, *, phase: str, trigger: str, profile: str, variant: str) -> dict:
    return {
        "seq": 0, "t": time.time(), "phase": phase, "trigger": trigger, "profile": profile, "variant": variant,
        "kind": "run.error", "detail": {"where": where, "message": message[:500]}, "outcome": "unknown",
        "attributed_to": "toolchain", "canary_match": [],
        "evidence": {"layer": "exec", "file": None, "line": None},
    }


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _sig(event: dict) -> tuple:
    detail = event.get("detail") or {}
    return (
        event.get("kind"), event.get("phase"), event.get("profile"), event.get("variant"),
        detail.get("path") or detail.get("dest") or detail.get("host") or detail.get("url") or "",
    )


def _tool_version(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip()
    return text.splitlines()[0][:80] if text else None


def _run_profile(
    profile: str,
    pkg: Path,
    triggers: Sequence[str],
    timeout_s: int,
    canaries: list[dict],
    *,
    backend: str,
    strace_on: bool,
    faketime: str | None,
) -> dict:
    work = Path(tempfile.mkdtemp(prefix=f"tl-{profile}-"))
    try:
        return _run_profile_in(
            work, profile, pkg, triggers, timeout_s, canaries,
            backend=backend, strace_on=strace_on, faketime=faketime,
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _run_profile_in(
    work: Path,
    profile: str,
    pkg: Path,
    triggers: Sequence[str],
    timeout_s: int,
    canaries: list[dict],
    *,
    backend: str,
    strace_on: bool,
    faketime: str | None,
) -> dict:
    penv = _build_world(profile, work, canaries)
    tools_ok = _copy_toolchain(work / "tools")
    target = _stage_package(pkg, work)
    shutil.copytree(AGENT_DIR, work / "agent", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    log_path, cov_path = work / "fp.jsonl", work / "cov.jsonl"
    log_path.touch()
    cov_path.touch()
    hostname = "ravi-laptop" if profile == "dev" else "fv-az123-456"
    cwd_default = "/w/home/work" if profile == "dev" else "/w/github/workspace"
    py = PY_BWRAP if backend == "bwrap" else "python3"
    strace_bin = "/usr/bin/strace" if backend == "bwrap" else "strace"
    bwrap = shutil.which("bwrap") or "bwrap"
    image = pick_image() if backend == "docker" else ""
    base_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/w/home",
        "FP_LOG": "/w/fp.jsonl",
        "FP_COV": "/w/cov.jsonl",
        "FP_CANARIES": "/w/canaries.json",
        "FP_PROFILE": profile,
        "FP_TOOL_DIRS": "/w/tools:/w/agent",
        "FP_IGNORE": "/w/fp.jsonl:/w/cov.jsonl:/w/canaries.json:/w/sinkhole.status",
        "PYTHONDONTWRITEBYTECODE": "1",
        "FP_SINKHOLE": "1",
        "FP_SINKHOLE_STATUS": "/w/sinkhole.status",
        **penv,
    }
    events: list[dict] = []
    ran: list[str] = []
    phases: set[str] = set()
    variants: set[str] = set()
    install_ok = False
    install_note = None if tools_ok else "setuptools/pip missing for the sandbox interpreter"
    files_added: list[str] = []
    scripts: list[tuple[str, str]] = []
    strace_ok = False
    baseline: set[str] = set()
    file_canaries = [(c["where"], c["id"]) for c in canaries if c["kind"] == "file"]

    def match_ids(blob: str) -> list[str]:
        from .agent.canarymatch import match_ids as match
        tokens = {c["token"]: c["id"] for c in canaries}
        return match(blob, tokens)

    def launch(inner: list[str], *, phase: str, trigger: str, variant: str, cwd: str, pypath: str,
               pkg_dirs: str, strace_name: str | None) -> subprocess.CompletedProcess | None:
        env = dict(base_env)
        env.update({
            "FP_PHASE": phase, "FP_TRIGGER": trigger, "FP_VARIANT": variant,
            "PYTHONPATH": pypath, "FP_PKG_DIRS": pkg_dirs,
        })
        if variant == "clock+30d":
            if faketime and backend == "bwrap":
                env["LD_PRELOAD"] = faketime
                env["FAKETIME"] = "+30d"
                env["DONT_FAKE_MONOTONIC"] = "1"
                env["FP_CLOCK"] = "libfaketime"
            else:
                env["FP_CLOCK"] = "python"
        argv = list(inner)
        if strace_on and strace_name:
            argv = [strace_bin, "-f", "-qq", "-s", "180", "-e", "trace=openat,connect,sendto,execve,clone",
                    "-o", f"/w/{strace_name}"] + argv
        if backend == "docker":
            cmd = docker_command(work=work, image=image, hostname=hostname, env=env, cwd=cwd, inner=argv)
        else:
            cmd = [
                bwrap, "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", str(work), "/w", "--ro-bind", str(work / "fake-etc"), "/etc",
                "--unshare-user", "--uid", "0", "--gid", "0",
                "--cap-add", "CAP_NET_BIND_SERVICE",
                "--unshare-net", "--unshare-pid", "--unshare-uts", "--unshare-ipc",
                "--hostname", hostname, "--die-with-parent", "--clearenv",
            ]
            if profile == "ci" and (work / "dockerenv").exists():
                cmd.extend(["--ro-bind", str(work / "dockerenv"), "/.dockerenv"])
            for key, value in env.items():
                cmd.extend(["--setenv", key, value])
            cmd.extend(["--chdir", cwd, *argv])
        ran.append(trigger)
        phases.add(phase)
        variants.add(variant)
        try:
            return subprocess.run(cmd, capture_output=True, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            events.append(_run_error(trigger, "timeout", phase=phase, trigger=trigger, profile=profile, variant=variant))
            return None

    def absorb_strace(name: str | None, *, phase: str, trigger: str, variant: str, known: list[dict]) -> None:
        nonlocal strace_ok
        if not (strace_on and name):
            return
        path = work / name
        if not path.exists() or path.stat().st_size == 0:
            return
        strace_ok = True
        fresh = parse_strace(
            path.read_text(encoding="utf-8", errors="replace"), baseline,
            phase=phase, trigger=trigger, profile=profile, variant=variant,
            file_canaries=file_canaries, match_ids=match_ids,
        )
        seen = {_sig(item) for item in known}
        for item in fresh:
            if _sig(item) in seen:
                continue
            events.append(item)
            seen.add(_sig(item))

    if strace_on:
        launch(
            # python -c pass, plus the distro helpers pip/setuptools exec (exact argv is subtracted).
            ["/bin/sh", "-c",
             f"{py} -c pass; "
             "lsb_release -a >/dev/null 2>&1 || true; "
             "uname -rs >/dev/null 2>&1 || true; "
             "uname -m >/dev/null 2>&1 || true; "
             "printf %s x | tr '[:lower:]' '[:upper:]' >/dev/null 2>&1 || true; "
             "printf %s x | tr '[:upper:]' '[:lower:]' >/dev/null 2>&1 || true; "
             "printf %s x | cut -c1 >/dev/null 2>&1 || true; "
             "printf %s x | cut -c2- >/dev/null 2>&1 || true"],
            phase="startup", trigger="strace_baseline", variant="default",
            cwd="/w", pypath="/w/agent", pkg_dirs="/w/site", strace_name="baseline.log",
        )
        base_log = work / "baseline.log"
        if base_log.exists():
            baseline = baseline_keys(base_log.read_text(encoding="utf-8", errors="replace"))
            strace_ok = True
        # The baseline is not a package trigger. Drop it from the reported set.
        if ran and ran[-1] == "strace_baseline":
            ran.pop()
        if "fresh_startup" not in triggers:
            phases.discard("startup")

    setup_text = ""
    setup_py = work / "site" / "setup.py"
    if setup_py.is_file():
        setup_text = setup_py.read_text(encoding="utf-8", errors="replace")

    def run_phase(inner: list[str], *, trigger: str, variant: str = "default", cwd: str, pypath: str, pkg_dirs: str) -> subprocess.CompletedProcess | None:
        phase = "cli" if trigger.startswith("cli:") else PHASE_OF.get(trigger, "import")
        before = _snapshot(work / "home")
        log_before = len(_read_jsonl(log_path))
        proc = launch(
            inner, phase=phase, trigger=trigger, variant=variant, cwd=cwd, pypath=pypath, pkg_dirs=pkg_dirs,
            strace_name=f"st-{trigger.replace(':', '_')}-{variant.replace('+', '')}.log",
        )
        produced = _read_jsonl(log_path)[log_before:]
        events.extend(produced)
        absorb_strace(
            f"st-{trigger.replace(':', '_')}-{variant.replace('+', '')}.log",
            phase=phase, trigger=trigger, variant=variant, known=produced,
        )
        events.extend(_home_diff_events(before, _snapshot(work / "home"), phase=phase, trigger=trigger, profile=profile, variant=variant))
        return proc

    if "install" in triggers:
        if not tools_ok:
            ran.append("install")
            phases.add("install")
            variants.add("default")
            events.append(_run_error("install", install_note or "toolchain missing", phase="install", trigger="install", profile=profile, variant="default"))
        else:
            proc = run_phase(
                [py, "-m", "pip", "install", "--no-index", "--no-build-isolation", "--no-deps",
                 "--disable-pip-version-check", "--no-warn-script-location", "--target", "/w/installed", target],
                trigger="install", cwd="/w/site" if (work / "site").is_dir() else "/w",
                pypath="/w/agent:/w/tools", pkg_dirs="/w/site:/w/installed",
            )
            if proc is None:
                install_ok = False
                install_note = (install_note or "") + "install timeout"
            elif proc.returncode != 0:
                install_ok = False
                err = (proc.stderr or b"").decode("utf-8", "replace")
                tail = " ".join(line.strip() for line in err.splitlines() if line.strip())[-400:]
                install_note = f"pip install exit {proc.returncode}: {tail}"
                events.append(_run_error("install", install_note, phase="install", trigger="install", profile=profile, variant="default"))
            else:
                install_ok = True
                install_note = None
        diff_events, files_added, scripts = diff_installed(work / "installed", profile=profile, setup_text=setup_text)
        events.extend(diff_events)
    elif setup_text:
        # Entry points still discovered from source when install was not requested.
        _, _, scripts = diff_installed(work / "installed", profile=profile, setup_text=setup_text)

    pkg_dirs = "/w/installed:/w/site" if install_ok else "/w/site"
    run_path = "/w/agent:/w/installed" if install_ok else "/w/agent:/w/site"

    if "fresh_startup" in triggers:
        run_phase(
            [py, "-S", "/w/agent/startup_bootstrap.py"],
            trigger="fresh_startup", cwd=cwd_default, pypath="/w/agent", pkg_dirs="/w/installed:/w/site",
        )
    if "import_all" in triggers:
        run_phase([py, "/w/agent/harness.py", "import"], trigger="import_all", cwd=cwd_default, pypath=run_path, pkg_dirs=pkg_dirs)
    if "call_all" in triggers:
        run_phase([py, "/w/agent/harness.py", "call"], trigger="call_all", cwd=cwd_default, pypath=run_path, pkg_dirs=pkg_dirs)
        run_phase([py, "/w/agent/harness.py", "call"], trigger="call_all", variant="clock+30d", cwd=cwd_default, pypath=run_path, pkg_dirs=pkg_dirs)
    if "cli" in triggers:
        if not scripts and setup_text:
            from .install_diff import console_scripts
            # setup(entry_points={"console_scripts": ["name=mod:func"]}) is not entry_points.txt.
            # A tiny scan of quoted name=mod:func pairs after console_scripts.
            if "console_scripts" in setup_text:
                scripts = console_scripts("[console_scripts]\n" + "\n".join(
                    part.strip().strip(",").strip("'\"") for part in setup_text.split("console_scripts", 1)[-1].splitlines()
                    if "=" in part and ":" in part
                ))
        for name, spec in scripts:
            for variant in ("default", "clock+30d"):
                run_phase(
                    [py, "/w/agent/harness.py", "cli", spec],
                    trigger=f"cli:{name}", variant=variant, cwd=cwd_default, pypath=run_path, pkg_dirs=pkg_dirs,
                )
                run_phase(
                    [py, "/w/agent/harness.py", "cli", spec, "--help"],
                    trigger=f"cli:{name}", variant=variant, cwd=cwd_default, pypath=run_path, pkg_dirs=pkg_dirs,
                )

    cov_tot = cov_ex = 0
    failed: list[str] = []
    native: list[str] = []
    for line in cov_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        cov_tot = max(cov_tot, int(row.get("callables_total") or 0))
        cov_ex = max(cov_ex, int(row.get("callables_exercised") or 0))
        failed.extend(row.get("modules_failed") or [])
        native.extend(row.get("native") or [])
    sinkhole = (work / "sinkhole.status").read_text(encoding="utf-8", errors="replace").startswith("ok") if (work / "sinkhole.status").exists() else False
    clock_ran = "clock+30d" in variants
    return {
        "events": events,
        "install_ok": install_ok,
        "install_note": install_note,
        "cov_tot": cov_tot,
        "cov_ex": cov_ex,
        "native": sorted(set(native)),
        "failed_mods": failed,
        "ran_triggers": ran,
        "phases": phases,
        "variants": variants,
        "files_added": files_added,
        "scripts": scripts,
        "strace_ok": strace_ok,
        "sinkhole": sinkhole,
        "clock_python_only": bool(clock_ran and not (faketime and backend == "bwrap")),
        "profile": profile,
    }


def _merge_notes(parts: list[dict]) -> str | None:
    notes = [p["install_note"] for p in parts if p.get("install_note")]
    return " | ".join(notes) if notes else None


def run_live(
    pkg_path: str,
    out_dir: str,
    *,
    profiles: Sequence[str],
    triggers: Sequence[str],
    timeout_s: int = 120,
    backend: str = "bwrap",
) -> dict:
    """Execute `pkg_path` inside the sandbox and write raw_events.jsonl + run_meta.json."""
    started = time.time()
    pkg = Path(pkg_path).resolve()
    if not pkg.exists():
        raise ValueError(f"package path does not exist: {pkg_path}")
    for profile in profiles:
        if profile not in {"dev", "ci"}:
            raise ValueError(f"unknown profile {profile!r}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    env = check_env()
    if backend == "bwrap" and not shutil.which("bwrap"):
        raise RuntimeError("bwrap not found; run scripts/check_env.sh")
    if backend == "docker" and not shutil.which("docker"):
        raise RuntimeError("docker not found")
    strace_on = bool(env.get("strace_in_bwrap")) if backend == "bwrap" else bool(env.get("strace"))
    faketime = env.get("libfaketime")
    canaries = _mint_canaries()
    trigger_list = list(triggers)

    def one(profile: str) -> dict:
        return _run_profile(
            profile, pkg, trigger_list, timeout_s, canaries,
            backend=backend, strace_on=strace_on, faketime=faketime,
        )

    # Profiles are independent (own work dir, own netns). A14: run them together.
    if len(tuple(profiles)) > 1:
        with ThreadPoolExecutor(max_workers=len(tuple(profiles))) as pool:
            parts = list(pool.map(one, profiles))
    else:
        parts = [one(profile) for profile in profiles]

    events: list[dict] = []
    for part in parts:
        events.extend(part["events"])
    profile_index = {name: i for i, name in enumerate(profiles)}
    events.sort(key=lambda e: (
        profile_index.get(e.get("profile"), 9),
        PHASE_ORDER.get(e.get("phase"), 9),
        e.get("t") or 0,
        e.get("seq", 0),
    ))
    raw = out / "raw_events.jsonl"
    with raw.open("w", encoding="utf-8") as fh:
        for index, event in enumerate(events):
            event["seq"] = index
            fh.write(json.dumps(event) + "\n")

    ran = sorted({item for part in parts for item in part["ran_triggers"]})
    phases = sorted({phase for part in parts for phase in part["phases"]}, key=lambda p: PHASE_ORDER.get(p, 9))
    variants = sorted({var for part in parts for var in part["variants"]}, key=lambda v: 0 if v == "default" else 1)
    if not variants:
        variants = ["default"]
    install_requested = "install" in trigger_list
    install_completed = all(part["install_ok"] for part in parts) if install_requested else False
    if install_requested and parts and all(part["install_ok"] for part in parts):
        install_completed = True
    strace_layer = any(part["strace_ok"] for part in parts)
    sinkhole = any(part["sinkhole"] for part in parts)
    clock_python_only = any(part["clock_python_only"] for part in parts)
    cli_found = any(part["scripts"] for part in parts) or any(item.startswith("cli:") for item in ran)
    failed = [mod for part in parts for mod in part["failed_mods"]]
    native = sorted({name for part in parts for name in part["native"]})
    not_obs = build_not_observed(
        triggers=trigger_list, ran_triggers=ran, variants=variants, strace_layer=strace_layer,
        sinkhole=sinkhole, clock_python_only=clock_python_only, install_completed=install_completed,
        install_requested=install_requested, cli_found=cli_found, failed_mods=failed,
    )
    cov_tot = max((part["cov_tot"] for part in parts), default=0)
    cov_ex = max((part["cov_ex"] for part in parts), default=0)
    files_added = sorted({path for part in parts for path in part["files_added"]})
    meta = {
        "run": {
            "sandbox": "docker" if backend == "docker" else "bwrap",
            "network": "sinkhole" if sinkhole else "blocked",
            "canaries": [c["id"] for c in canaries],
            "phases": phases,
            "profiles": list(profiles),
            "variants": variants,
            "started_at": datetime.fromtimestamp(started, UTC).isoformat(),
            "duration_s": round(time.time() - started, 2),
            "stub": False,
            "tool_versions": {
                "python": _tool_version([PY_BWRAP, "--version"]),
                "bwrap": _tool_version(["bwrap", "--version"]) if backend == "bwrap" else None,
                "strace": _tool_version(["strace", "-V"]) if strace_layer else None,
                "libfaketime": faketime,
            },
        },
        "coverage": {
            "phases_run": phases,
            "profiles_run": list(profiles),
            "variants_run": variants,
            "triggers_run": ran,
            "install_completed": install_completed,
            "install_note": _merge_notes(parts),
            "network": "sinkhole" if sinkhole else "blocked",
            "callables_total": cov_tot,
            "callables_exercised": cov_ex,
            "native_skipped": native,
            "strace_layer": strace_layer,
            "not_observed": not_obs,
        },
        "canaries": _public_canaries(canaries),
        "files_added": files_added,
    }
    meta_path = out / "run_meta.json"
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return {"raw_events_path": str(raw), "run_meta_path": str(meta_path), "run_meta": meta}
