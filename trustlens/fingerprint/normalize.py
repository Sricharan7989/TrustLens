"""Dev B: raw events -> fingerprint (capability-tagged, ordered, attributed, noise-filtered).

STUB-LEVEL v0 that already works on the fixtures. TODO(Dev B): richer path/env classifiers, baseline subtraction from
strace noise, dependency attribution, whitelist loader merge with bench/calibration/noise_whitelist.yaml, unit tests.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

from trustlens.contracts import ROOT, iter_jsonl

SENSITIVE_PATH = re.compile(r"(\.ssh/|\.aws/|\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.kube/|\.docker/config|\.config/gcloud|\.azure/|"
                            r"\.mozilla/|\.config/google-chrome|Library/Application Support|/etc/shadow|\.gnupg/|\.bash_history)")
PERSIST_PATH = re.compile(r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|crontab|/cron\.|\.config/autostart|\.config/systemd|\.git/hooks|authorized_keys|/etc/init|rc\.local)")
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AWS_|GITHUB_|GITLAB_|NPM_|PYPI_|SSH_)", re.I)
PROBE_ENV = {"CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "JENKINS_URL", "BUILDKITE", "CIRCLECI", "CONTAINER", "KUBERNETES_SERVICE_HOST"}
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


def _whitelisted(cap: str, detail: dict, rules: list[dict]) -> bool:
    for r in rules:
        if r.get("capability") != cap:
            continue
        for key, field in (("path_glob", "path"), ("host_glob", "host"), ("env_glob", "name")):
            if key in r and fnmatch.fnmatch(str(detail.get(field, detail.get("dest", ""))), r[key]):
                return True
    return False


def classify(e: dict) -> tuple[str | None, dict]:
    """raw event -> (capability or None to drop, normalized detail)."""
    k, d = e["kind"], dict(e.get("detail", {}))
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
        return "subprocess", d
    if k == "env.read":
        n = d.get("name", "")
        if n in PROBE_ENV:
            return "sandbox_probe", d
        return ("env_secrets", d) if SECRET_ENV.search(n) else (None, d)
    if k in ("dyn.exec", "dyn.compile"):
        return "dynamic_exec", d
    if k == "install.hook":
        return "install_hook", d
    if k == "startup.sitecustomize":
        return "startup_hook", d
    if k == "startup.pth":
        return ("startup_hook", d) if str(d.get("line_text", "")).lstrip().startswith(("import ", "import\t")) else (None, d)
    if k == "native.load":
        return "native_code", d
    return None, d


def build_fingerprint(raw_events_path: str, run_meta: dict, package: dict, static_signals: list[dict] | None = None,
                      whitelist: list[dict] | None = None) -> dict:
    rules = _load_whitelist() if whitelist is None else whitelist
    events, dropped = [], 0
    for e in iter_jsonl(raw_events_path):
        if e.get("attributed_to") == "toolchain":
            dropped += 1
            continue
        cap, detail = classify(e)
        if cap is None or _whitelisted(cap, detail, rules):
            dropped += 1
            continue
        cm = list(e.get("canary_match") or [])
        events.append({"id": f"ev{len(events)}", "seq": e["seq"], "phase": e["phase"], "trigger": e["trigger"], "profile": e["profile"],
                       "variant": e["variant"], "capability": cap, "detail": detail, "canary_hit": bool(cm), "canary_ids": cm,
                       "outcome": e["outcome"], "attributed_to": e.get("attributed_to", "unknown"), "evidence": e.get("evidence") or {}})
    combos = {(p, v) for p in run_meta["coverage"]["profiles_run"] for v in (run_meta["coverage"].get("variants_run") or ["default"])}
    summary: dict[str, dict] = {}
    for cap in sorted({ev["capability"] for ev in events}):
        evs = [ev for ev in events if ev["capability"] == cap]
        seen = {(ev["profile"], ev["variant"]) for ev in evs}
        summary[cap] = {"phases": sorted({ev["phase"] for ev in evs}), "profiles": sorted({ev["profile"] for ev in evs}),
                        "conditional": bool(combos) and seen != combos, "count": len(evs), "canary_hit": any(ev["canary_hit"] for ev in evs)}
    cov = dict(run_meta["coverage"], whitelisted_or_dropped_events=dropped)
    return {"schema_version": "1.0", "package": package, "run": run_meta["run"], "events": events, "static_signals": static_signals or [],
            "coverage": cov, "canaries": run_meta.get("canaries", []), "capability_summary": summary}
