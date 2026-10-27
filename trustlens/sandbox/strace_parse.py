"""Parse a narrow strace log into raw events and subtract a python -c pass baseline."""
from __future__ import annotations

import re
import time

_LINE = re.compile(
    r"^(?:\d+\s+)?(?P<call>openat|connect|sendto|execve|clone)\((?P<body>.*)\)\s*=\s*(?P<ret>-?\d+)",
    re.DOTALL,
)
_QUOTED = re.compile(r'"((?:\\.|[^"\\])*)"')
_INET = re.compile(r'inet_addr\("([^"]+)"\)')
_PORT = re.compile(r"htons\((\d+)\)")
_SKIP_PREFIXES = (
    "/usr/", "/lib/", "/lib64/", "/proc/", "/dev/", "/sys/", "/etc/",
    "/w/tools/", "/w/agent/", "/w/fp.jsonl", "/w/cov.jsonl", "/w/canaries.json",
    "/tmp/", "/usr/bin/python", "/usr/bin/strace",
)


def _unescape(text: str) -> str:
    return text.replace(r"\n", "\n").replace(r"\t", "\t").replace(r"\"", '"').replace(r"\\", "\\")


def _quotes(body: str) -> list[str]:
    return [_unescape(part) for part in _QUOTED.findall(body)]


_UNFINISHED = re.compile(r"^(?P<pid>\d+)\s+(?P<head>.*?)\s*<unfinished \.\.\.>\s*$")
_RESUMED = re.compile(r"^(?P<pid>\d+)\s+<\.\.\. (?P<call>\w+) resumed>(?P<tail>.*)$")


def stitch_lines(text: str) -> list[str]:
    """Rejoin syscalls that `strace -f` split across lines.

    When two traced processes make syscalls at the same moment (pipelines, or any
    run on a busy machine), strace writes `pid call(args <unfinished ...>` and later
    `pid <... call resumed>rest) = ret`. Neither half matches a complete syscall, so
    without this the event is silently lost. Losing it in the baseline made helper
    execs (`tr`, `cut`) leak into package runs as proc.spawn under parallel load.
    """
    pending: dict[str, str] = {}
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        unfinished = _UNFINISHED.match(line)
        if unfinished:
            pending[unfinished.group("pid")] = unfinished.group("pid") + " " + unfinished.group("head")
            continue
        resumed = _RESUMED.match(line)
        if resumed:
            head = pending.pop(resumed.group("pid"), None)
            if head is not None and head.split(" ", 1)[-1].startswith(resumed.group("call") + "("):
                lines.append(head + resumed.group("tail"))
            continue
        lines.append(line)
    return lines


def baseline_keys(text: str) -> set[str]:
    """Syscall fingerprints from a python -c pass run. Paths and exec targets only."""
    keys: set[str] = set()
    for raw in stitch_lines(text):
        match = _LINE.search(raw.strip())
        if not match:
            continue
        call = match.group("call")
        quotes = _quotes(match.group("body"))
        if call == "openat" and quotes:
            keys.add("open:" + quotes[0])
        elif call == "execve" and quotes:
            keys.add("exec:" + quotes[0])
            keys.add("execargv:" + "\0".join(quotes))
        elif call == "connect":
            ip = _INET.search(match.group("body"))
            if ip:
                keys.add("conn:" + ip.group(1))
    return keys


_SENSITIVE = (
    "/.ssh/", "/.aws/", "/.npmrc", "/.docker/", "/.config/gcloud/", "/.gitconfig",
    "/.bashrc", "/.profile", "/.bash_profile", "/.zshrc", "id_rsa", "/.dockerenv",
    "/proc/1/cgroup", "/proc/uptime", "/proc/cpuinfo",
)


def _interesting_open(path: str) -> bool:
    """Canary and probe opens, plus native libraries shipped by the package."""
    if path.endswith(".pyc") or "/__pycache__/" in path:
        return False
    if ".dist-info/" in path or ".egg-info/" in path:
        return False
    # Sensitive markers win over the /proc and /etc skips so native probes of
    # /proc/1/cgroup, /proc/uptime, /proc/cpuinfo and /.dockerenv are kept.
    if any(marker in path for marker in _SENSITIVE):
        return True
    if path.startswith(_SKIP_PREFIXES):
        return False
    return path.endswith(".so") and ("/w/installed/" in path or "/w/site/" in path)


def parse_strace(
    text: str,
    baseline: set[str],
    *,
    phase: str,
    trigger: str,
    profile: str,
    variant: str,
    file_canaries: list[tuple[str, str]],
    match_ids,
) -> list[dict]:
    """Turn strace lines the audit hook cannot see into raw events. `match_ids(text) -> list[str]`."""
    events: list[dict] = []
    now = time.time()

    def add(kind: str, detail: dict, outcome: str, blob: str) -> None:
        events.append({
            "seq": 0,
            "t": now,
            "phase": phase,
            "trigger": trigger,
            "profile": profile,
            "variant": variant,
            "kind": kind,
            "detail": detail,
            "outcome": outcome,
            "attributed_to": "pkg",
            "canary_match": match_ids(blob),
            "evidence": {"layer": "strace", "file": None, "line": None, "syscall": kind.split(".")[0]},
        })

    for raw in stitch_lines(text):
        match = _LINE.search(raw.strip())
        if not match:
            continue
        call = match.group("call")
        body = match.group("body")
        ret = int(match.group("ret"))
        quotes = _quotes(body)
        if call == "openat" and quotes:
            path = quotes[0]
            if "open:" + path in baseline or not _interesting_open(path):
                continue
            ids = [cid for suffix, cid in file_canaries if path.endswith("/" + suffix) or path.endswith(suffix)]
            if path.endswith(".so") and ("/w/installed/" in path or "/w/site/" in path):
                add("native.load", {"path": path}, "succeeded" if ret >= 0 else "attempted", path)
                continue
            writing = "O_WRONLY" in body or "O_RDWR" in body or "O_CREAT" in body
            events.append({
                "seq": 0,
                "t": now,
                "phase": phase,
                "trigger": trigger,
                "profile": profile,
                "variant": variant,
                "kind": "file.write" if writing else "file.read",
                "detail": {"path": path, "mode": "strace"},
                "outcome": "succeeded" if ret >= 0 else "attempted",
                "attributed_to": "pkg",
                "canary_match": sorted(set(ids)),
                "evidence": {"layer": "strace", "file": None, "line": None, "syscall": "openat"},
            })
        elif call == "connect":
            ip_match = _INET.search(body)
            port_match = _PORT.search(body)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if "conn:" + ip in baseline or ip.startswith("127."):
                continue
            dest = ip + (":" + port_match.group(1) if port_match else "")
            add("net.connect", {"dest": dest}, "blocked" if ret < 0 else "succeeded", dest)
        elif call == "sendto" and quotes:
            blob = quotes[0][:200]
            dest = ""
            ip_match = _INET.search(body)
            if ip_match:
                dest = ip_match.group(1)
            # 127.0.0.1 is the loopback sinkhole (glibc's DNS query). The audit hook
            # records the package's own socket.send; this copy is toolchain traffic.
            if dest.startswith("127."):
                continue
            add("net.send", {"dest": dest, "data_head": blob}, "attempted" if ret < 0 else "succeeded", blob)
        elif call == "execve" and quotes:
            exe = quotes[0]
            argv = quotes[1:] or [exe]
            base = exe.rsplit("/", 1)[-1]
            # pip/setuptools probes the distro via lsb_release, which shells out to
            # getopt. strace has no Python frame, so those would be blamed on the package.
            if base == "lsb_release" or (base == "getopt" and "lsb_release" in argv):
                continue
            if exe.startswith("/usr/bin/python") or exe.endswith("/strace"):
                continue
            # Same argv as the baseline (python -c pass, or lsb_release and its helpers).
            # Match the full argv, not just the executable, so a different `tr` still shows.
            if "execargv:" + "\0".join(quotes) in baseline:
                continue
            add("proc.spawn", {"argv": argv, "via": "execve"}, "succeeded" if ret >= 0 else "attempted", " ".join(argv))
    return events
