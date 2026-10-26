"""Dev B: raw events -> fingerprint (capability-tagged, ordered, attributed, noise-filtered)."""
from __future__ import annotations

import copy
import fnmatch
import re
from pathlib import Path

import yaml

from trustlens.contracts import ROOT, iter_jsonl

SENSITIVE_PATH = re.compile(
    r"(\.ssh/|id_rsa|\.aws/|\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.kube/|\.docker/config|\.config/gcloud|\.azure/|"
    r"\.mozilla/|\.config/google-chrome|Library/Application Support|/etc/shadow|/etc/passwd|\.gnupg/|\.bash_history)",
    re.I,
)
PERSIST_PATH = re.compile(
    r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.bash_login|\.zprofile|"
    r"crontab|/cron\b|/cron\.|/var/spool/cron|"
    r"\.config/autostart|\.config/systemd|systemd/user|"
    r"authorized_keys|\.ssh/authorized_keys|/etc/init\.d|rc\.local|\.git/hooks)"
)
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AWS_|GITHUB_|GITLAB_|NPM_|PYPI_|SSH_)", re.I)
PROBE_ENV = {
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "JENKINS_URL",
    "BUILDKITE", "CIRCLECI", "CONTAINER", "KUBERNETES_SERVICE_HOST",
    "HOSTNAME", "NUMBER_OF_PROCESSORS"
}
PROBE_PATH = ("/.dockerenv", "/proc/1/cgroup", "/proc/uptime", "/proc/self/cgroup", "/proc/cpuinfo")
SAFE_WRITE = re.compile(r"^(/tmp/|/var/tmp/|/w/site/|/pkg/|/w/[^/]+\.egg-info|~/\.cache/|.*/site-packages/)")


def _home(p: str) -> str:
    p = p.replace("/w/home/", "~/").replace("/w/home", "~")
    return p


def _load_whitelist() -> list[dict]:
    rules: list[dict] = []
    for f in (Path(__file__).resolve().parent.parent / "engine" / "noise_whitelist.yaml", ROOT / "bench" / "calibration" / "noise_whitelist.yaml"):
        if f.exists():
            rules += (yaml.safe_load(f.read_text()) or {}).get("rules", [])
    return rules


def _whitelisted(cap: str, detail: dict, rules: list[dict], has_canary: bool = False) -> bool:
    if has_canary:
        return False
    for r in rules:
        if r.get("capability") != cap:
            continue
        for key, field in (("path_glob", "path"), ("host_glob", "host"), ("env_glob", "name")):
            if key in r and fnmatch.fnmatch(str(detail.get(field, detail.get("dest", ""))), r[key]):
                return True
    return False


def classify(e: dict, written_paths: set[str] | None = None, net_seen: set[tuple[str, str]] | None = None) -> tuple[str | None, dict]:
    """raw event -> (capability or None to drop, normalized detail)."""
    k = e.get("kind")
    d = dict(e.get("detail") or {})
    if not k:
        return None, d
    cm = list(e.get("canary_match") or [])
    if cm:
        if str(k).startswith("file."):
            p = _home(d.get("path", ""))
            d["path"] = p
            return "fs_read_sensitive", d
        if str(k).startswith("env."):
            return "env_secrets", d
    if k == "file.read":
        p = _home(d.get("path", ""))
        d["path"] = p
        if p in PROBE_PATH:
            return "sandbox_probe", d
        return ("fs_read_sensitive", d) if SENSITIVE_PATH.search(p) else (None, d)
    if k in ("file.write", "file.new"):
        p = _home(d.get("path", ""))
        d["path"] = p
        if PERSIST_PATH.search(p):
            return "persistence", d
        return (None, d) if SAFE_WRITE.match(p) or not p.startswith(("~", "/")) else ("fs_write_outside_pkg", d)
    if k in ("net.dns", "net.connect", "net.send", "net.http"):
        if e.get("canary_match"):
            d["canary_in_bytes"] = True
        return "network", d
    if k == "proc.spawn":
        argv = d.get("argv") or []
        argv_str = " ".join(argv) if isinstance(argv, list) else str(argv)
        via = str(d.get("via", ""))
        if written_paths and any(wp for wp in written_paths if wp and (wp in argv_str or wp in via or any(wp == arg or arg.endswith("/" + Path(wp).name) for arg in (argv if isinstance(argv, list) else [])))):
            d["lineage"] = "download_exec"
            return "download_exec", d
        if d.get("lineage") == "download_exec":
            return "download_exec", d
        return "subprocess", d
    if k == "env.read":
        n = d.get("name", "")
        if n in PROBE_ENV:
            return "sandbox_probe", d
        return ("env_secrets", d) if SECRET_ENV.search(n) else (None, d)
    if k in ("dyn.exec", "dyn.compile"):
        co_fn = str(d.get("co_filename", ""))
        prof_var = (e.get("profile", ""), e.get("variant", ""))
        has_net = net_seen and prof_var in net_seen
        has_written = written_paths and any(wp for wp in written_paths if wp and (wp == co_fn or co_fn.endswith(wp)))
        if has_written or has_net:
            d["lineage"] = "download_exec"
            return "download_exec", d
        return "dynamic_exec", d
    if k == "install.hook":
        return "install_hook", d
    if k == "startup.sitecustomize":
        d["executes_code"] = True
        return "startup_hook", d
    if k == "startup.pth":
        line = str(d.get("line_text", "")).strip()
        if not line:
            return None, d
        is_exec = (
            line.startswith(("import ", "import\t"))
            or any(kw in line for kw in ("exec(", "eval(", "base64", "__import__"))
            or (";" in line and "import" in line)
        )
        if is_exec:
            d["executes_code"] = True
            return "startup_hook", d
        d["executes_code"] = False
        d["path_only"] = True
        return "startup_hook", d
    if k == "native.load":
        return "native_code", d
    return None, d


def build_fingerprint(raw_events_path: str, run_meta: dict, package: dict, static_signals: list[dict] | None = None,
                      whitelist: list[dict] | None = None) -> dict:
    rules = _load_whitelist() if whitelist is None else whitelist
    events, dropped = [], 0
    written_paths: set[str] = set()
    net_seen: set[tuple[str, str]] = set()
    seen_events: dict[tuple, int] = {}
    cov_coverage = copy.deepcopy(run_meta.get("coverage") or {})

    for e in iter_jsonl(raw_events_path):
        if not isinstance(e, dict):
            continue
        if e.get("detail") is None:
            e["detail"] = {}
        is_toolchain = e.get("attributed_to") == "toolchain"
        if e.get("kind") == "run.error":
            cov_coverage["run_error"] = True
            msg = str(e.get("detail", {}).get("message", ""))
            if "timeout" in msg.lower():
                cov_coverage["run_timeout"] = True
            not_obs = cov_coverage.setdefault("not_observed", [])
            phase = e.get("phase", "execution")
            err_line = f"Error during {phase}: {msg}" if msg else f"Error during {phase}"
            if err_line not in not_obs:
                not_obs.append(err_line)

        if is_toolchain:
            dropped += 1
            continue
        if e.get("kind") in ("file.write", "file.new"):
            wp = _home(e.get("detail", {}).get("path", ""))
            if wp:
                written_paths.add(wp)
        if e.get("kind") in ("net.http", "net.send"):
            net_seen.add((e.get("profile", ""), e.get("variant", "")))

        cap, detail = classify(e, written_paths, net_seen)
        cm = list(e.get("canary_match") or [])
        has_canary = bool(cm) or bool(detail.get("canary_in_bytes"))

        if has_canary and cap is None:
            if str(e.get("kind", "")).startswith("env."):
                cap = "env_secrets"
            else:
                cap = "fs_read_sensitive"

        if not has_canary and (cap is None or _whitelisted(cap, detail, rules, has_canary=has_canary)):
            dropped += 1
            continue

        detail_target = str(detail.get("path") or detail.get("name") or detail.get("dest") or detail.get("host") or detail.get("url") or detail.get("argv") or detail.get("file") or "")
        dedupe_key = (
            e["phase"], e["trigger"], e["profile"], e["variant"],
            cap, e["outcome"], e.get("attributed_to", "unknown"),
            detail_target,
            detail.get("decoded_snippet"),
            detail.get("co_filename"),
            detail.get("url"),
            detail.get("host"),
            detail.get("dest"),
            bool(cm)
        )
        if dedupe_key in seen_events:
            idx = seen_events[dedupe_key]
            existing_ev = events[idx]
            existing_ev["detail"]["count"] = existing_ev["detail"].get("count", 1) + 1
            existing_ev["count"] = existing_ev.get("count", 1) + 1
            for cid in cm:
                if cid not in existing_ev["canary_ids"]:
                    existing_ev["canary_ids"].append(cid)
            dropped += 1
            continue

        ev_idx = len(events)
        seen_events[dedupe_key] = ev_idx
        events.append({
            "id": f"ev{ev_idx}", "seq": e["seq"], "phase": e["phase"], "trigger": e["trigger"],
            "profile": e["profile"], "variant": e["variant"], "capability": cap, "detail": detail,
            "canary_hit": bool(cm), "canary_ids": cm, "outcome": e["outcome"],
            "attributed_to": e.get("attributed_to", "unknown"), "evidence": e.get("evidence") or {}
        })
    combos = {(p, v) for p in run_meta["coverage"]["profiles_run"] for v in (run_meta["coverage"].get("variants_run") or ["default"])}
    summary: dict[str, dict] = {}
    for cap in sorted({ev["capability"] for ev in events}):
        evs = [ev for ev in events if ev["capability"] == cap]
        seen = {(ev["profile"], ev["variant"]) for ev in evs}
        summary[cap] = {"phases": sorted({ev["phase"] for ev in evs}), "profiles": sorted({ev["profile"] for ev in evs}),
                        "conditional": bool(combos) and seen != combos, "count": len(evs), "canary_hit": any(ev["canary_hit"] for ev in evs)}
    cov = dict(cov_coverage, whitelisted_or_dropped_events=dropped)
    return {"schema_version": "1.0", "package": package, "run": run_meta.get("run", {}), "events": events, "static_signals": list(static_signals or []),
            "coverage": cov, "canaries": run_meta.get("canaries", []), "capability_summary": summary}
