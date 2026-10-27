"""Dev B: raw events -> fingerprint (capability-tagged, ordered, attributed, noise-filtered)."""
from __future__ import annotations

import copy
import fnmatch
import re
from pathlib import Path

import yaml

from trustlens.contracts import ROOT, iter_jsonl

SENSITIVE_PATH = re.compile(
    r"(\.ssh/|(?<![A-Za-z0-9])id_rsa|\.aws/|\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.kube/|\.docker/config|\.config/gcloud|\.azure/|"
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
# Decoded snippets: rejoin split literals, then match sensitive paths and real env reads.
# A bare all-caps token (TOKEN = None, for KEY, help='Set API_KEY') is not a secret read.
_STR_LIT = r"""(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""
_LITERAL_JOIN_RE = re.compile(rf"(?P<left>{_STR_LIT})\s*(?P<op>[+/])\s*(?P<right>{_STR_LIT})")
# Implicit concat: '/etc/' 'passwd'. Whitespace only, so commas between args stay put.
_IMPLICIT_CONCAT_RE = re.compile(rf"(?P<left>{_STR_LIT})\s+(?P<right>{_STR_LIT})")
_OS_PATH_JOIN_RE = re.compile(
    rf"""os\.path\.join\s*\(\s*(?P<left>{_STR_LIT})\s*,\s*(?P<right>{_STR_LIT})"""
)
_GETATTR_ENVIRON_RE = re.compile(r"""getattr\s*\(\s*os\s*,\s*(['"])environ\1\s*\)""")
_ENV_COPY_RE = re.compile(r"""os\.environ\s*\.\s*copy\s*\(\s*\)""")
_DICT_ENVIRON_RE = re.compile(r"""dict\s*\(\s*os\.environ\s*\)""")
# Optional f/r/b (or fr/rf/rb/br) prefix so os.environ[f'NAME'] still yields NAME.
_STR_PREFIX = r"""(?:[fFrRbB]{1,2})?"""
_ENV_LOOKUP_RE = re.compile(
    rf"""os\.environ\s*\[\s*{_STR_PREFIX}(['"])(?P<idx>[^'"]+)\1"""
    rf"""|os\.environ\.get\s*\(\s*{_STR_PREFIX}(['"])(?P<get>[^'"]+)\3"""
    rf"""|os\.getenv\s*\(\s*{_STR_PREFIX}(['"])(?P<getenv>[^'"]+)\5"""
)
# Names that are secrets even when they do not contain _SECRET or end in _TOKEN.
_CURATED_SECRET_ENV = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITLAB_TOKEN",
    "GITLAB_PRIVATE_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PYPI_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "ARM_CLIENT_SECRET",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_API_KEY",
    "SENDGRID_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "TWILIO_AUTH_TOKEN",
    "DOCKER_PASSWORD",
    "PYPI_PASSWORD",
    "TWINE_PASSWORD",
    "SECRET_KEY",
    "API_KEY",
    "API_TOKEN",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "SESSION_TOKEN",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
})
# Looked up often, but not credentials. Never treat these as env secrets.
_NON_SECRET_ENV = frozenset({
    "SSH_AUTH_SOCK",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_DEFAULT_OUTPUT",
    "AWS_PROFILE",
    "AWS_ACCOUNT_ID",
    "AWS_SDK_LOAD_CONFIG",
})
PROBE_ENV = {
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "JENKINS_URL",
    "BUILDKITE", "CIRCLECI", "CONTAINER", "KUBERNETES_SERVICE_HOST",
    "HOSTNAME", "NUMBER_OF_PROCESSORS"
}
PROBE_PATH = ("/.dockerenv", "/proc/1/cgroup", "/proc/uptime", "/proc/self/cgroup", "/proc/cpuinfo")
SAFE_WRITE = re.compile(r"^(/tmp/|/var/tmp/|/w/site/|/pkg/|/w/[^/]+\.egg-info|~/\.cache/|.*/site-packages/)")


def _quote_bodies(left: str, right: str, sep: str) -> str:
    quote = left[0]
    return quote + left[1:-1] + sep + right[1:-1] + quote


def _join_literal_match(match: re.Match[str]) -> str:
    sep = "/" if match.group("op") == "/" else ""
    return _quote_bodies(match.group("left"), match.group("right"), sep)


def _implicit_concat_match(match: re.Match[str]) -> str:
    return _quote_bodies(match.group("left"), match.group("right"), "")


def _path_join_match(match: re.Match[str]) -> str:
    left, right = match.group("left"), match.group("right")
    lbody, rbody = left[1:-1], right[1:-1]
    if lbody.endswith("/"):
        joined = lbody + rbody.lstrip("/")
    elif rbody.startswith("/"):
        joined = lbody.rstrip("/") + rbody
    else:
        joined = lbody + "/" + rbody
    return left[0] + joined + left[0]


_DUNDER_IMPORT_OS_RE = re.compile(r"""__import__\s*\(\s*(['"])os\1\s*\)\s*\.""")
_IMPORT_OS_AS_RE = re.compile(r"""\bimport\s+(?:[\w.]+\s*(?:as\s+\w+)?\s*,\s*)*os\s+as\s+(?P<alias>\w+)""")
_FROM_OS_IMPORT_RE = re.compile(
    r"""\bfrom\s+os\s+import\s+(?:\((?P<paren>[\w\s,]+)\)|(?P<names>[\w \t,]+))"""
)


def _canonicalize_env_reads(text: str) -> str:
    """Turn aliased environ reads into os.environ / os.getenv so the lookup regex can see them.

    Covers `import os as o`, `from os import environ as e, getenv as g`, `__import__('os')`,
    `getattr(os, 'environ')`, `os.environ.copy()` and `dict(os.environ)`.
    """
    text = _DUNDER_IMPORT_OS_RE.sub("os.", text)
    text = _GETATTR_ENVIRON_RE.sub("os.environ", text)
    text = _ENV_COPY_RE.sub("os.environ", text)
    text = _DICT_ENVIRON_RE.sub("os.environ", text)
    for match in _IMPORT_OS_AS_RE.finditer(text):
        alias = re.escape(match.group("alias"))
        text = re.sub(rf"(?<![\w.]){alias}\s*\.\s*(environ|getenv)\b", r"os.\1", text)
    for match in _FROM_OS_IMPORT_RE.finditer(text):
        for part in (match.group("paren") or match.group("names") or "").split(","):
            bits = part.split()
            if not bits or bits[0] not in ("environ", "getenv"):
                continue
            name = bits[2] if len(bits) == 3 and bits[1] == "as" else bits[0]
            if bits[0] == "environ":
                text = re.sub(rf"(?<![\w.]){re.escape(name)}\s*(\[|\.get\s*\()", r"os.environ\1", text)
            else:
                text = re.sub(rf"(?<![\w.]){re.escape(name)}\s*\(", "os.getenv(", text)
    return text


def normalize_decoded_snippet(snippet: str) -> str:
    """Reassemble split string literals so denylist markers are contiguous."""
    text = _canonicalize_env_reads(snippet)
    for _ in range(32):
        updated = _LITERAL_JOIN_RE.sub(_join_literal_match, text)
        updated = _IMPLICIT_CONCAT_RE.sub(_implicit_concat_match, updated)
        updated = _OS_PATH_JOIN_RE.sub(_path_join_match, updated)
        if updated == text:
            return text
        text = updated
    return text


_SECRET_NAME_PART_RE = re.compile(r"(?:^|_)(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY|API_KEY)(?:_|$)")


def _env_name_is_secret(name: str) -> bool:
    """True for a curated secret name, a secret word as a whole name part, or a *_TOKEN / *_KEY suffix.

    Whole name parts only: DB_PASSWORD, SSH_PRIVATE_KEY and SERVICE_CREDENTIALS are secrets;
    MY_TOKEN_COUNT and PRIMARY_KEYBOARD are not.
    """
    upper = name.strip().upper()
    if not upper or upper in PROBE_ENV or upper in _NON_SECRET_ENV:
        return False
    if upper in _CURATED_SECRET_ENV:
        return True
    if _SECRET_NAME_PART_RE.search(upper):
        return True
    return upper.endswith("_TOKEN") or upper.endswith("_KEY")


def snippet_mentions_env_secret(snippet: str) -> bool:
    """True when a decoded snippet reads a real secret env name, not a loose token."""
    normalized = normalize_decoded_snippet(snippet)
    for match in _ENV_LOOKUP_RE.finditer(normalized):
        name = match.group("idx") or match.group("get") or match.group("getenv") or ""
        if _env_name_is_secret(name):
            return True
    return False


def snippet_has_denylisted_secret(snippet: str) -> bool:
    """True when a decoded snippet touches a sensitive path or reads a real secret env name."""
    normalized = normalize_decoded_snippet(snippet)
    if SENSITIVE_PATH.search(normalized):
        return True
    return snippet_mentions_env_secret(normalized)


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
    # Canary promotion is only for reads. file.write/file.new must still reach PERSIST_PATH.
    if cm and k == "file.read":
        p = _home(d.get("path", ""))
        d["path"] = p
        return "fs_read_sensitive", d
    if cm and k == "env.read":
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
