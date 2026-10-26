"""strace second layer: parser unit tests and a libc open the audit hook cannot see."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl, validate
from trustlens.sandbox import check_env, run_package
from trustlens.sandbox.strace_parse import baseline_keys, parse_strace

DATA = Path(__file__).parent / "data"
ENV = check_env()
bwrap_ok = ENV.get("bwrap_ok")
strace_ok = ENV.get("strace_in_bwrap")

SAMPLE = """\
5 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3
5 openat(AT_FDCWD, "/w/home/.ssh/id_rsa", O_RDONLY) = 4
5 openat(AT_FDCWD, "/w/installed/native_open/evil.so", O_RDONLY) = 5
5 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.51.100.7")}, 16) = -1
5 sendto(3, "TLCANARYSSHKEY", 14, 0, NULL, 0) = 14
5 execve("/bin/echo", ["/bin/echo", "hi"], 0x1) = 0
5 execve("/usr/bin/lsb_release", ["/usr/bin/lsb_release", "-a"], 0x1) = 0
5 execve("/usr/bin/getopt", ["/usr/bin/getopt", "--name", "lsb_release", "-a"], 0x1) = 0
5 execve("/usr/bin/tr", ["/usr/bin/tr", "[:upper:]", "[:lower:]"], 0x1) = 0
5 execve("/usr/bin/tr", ["/usr/bin/tr", "TLCANARY"], 0x1) = 0
5 sendto(3, "noise", 5, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 5
"""
BASE = """\
5 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3
5 execve("/usr/bin/python3", ["/usr/bin/python3", "-c", "pass"], 0x1) = 0
5 execve("/usr/bin/tr", ["/usr/bin/tr", "[:upper:]", "[:lower:]"], 0x1) = 0
"""


def test_strace_parser_subtracts_baseline_and_keeps_canary():
    baseline = baseline_keys(BASE)
    rows = parse_strace(
        SAMPLE, baseline, phase="call", trigger="call_all", profile="dev", variant="default",
        file_canaries=[(".ssh/id_rsa", "ssh_key")], match_ids=lambda text: ["ssh_key"] if "TLCANARY" in text else [],
    )
    kinds = {(row["kind"], row["detail"].get("path") or row["detail"].get("dest") or row["detail"].get("data_head")) for row in rows}
    assert ("file.read", "/w/home/.ssh/id_rsa") in {(row["kind"], row["detail"].get("path")) for row in rows}
    assert any(row["kind"] == "native.load" and row["detail"]["path"].endswith(".so") for row in rows)
    assert any(row["kind"] == "net.connect" and row["detail"]["dest"] == "198.51.100.7:80" for row in rows)
    assert any(row["kind"] == "net.send" and "ssh_key" in row["canary_match"] for row in rows)
    assert any(row["kind"] == "proc.spawn" and row["detail"]["argv"][0] == "/bin/echo" for row in rows)
    assert any(row["kind"] == "proc.spawn" and row["detail"]["argv"] == ["/usr/bin/tr", "TLCANARY"] for row in rows)
    assert not any(row["detail"].get("argv") == ["/usr/bin/tr", "[:upper:]", "[:lower:]"] for row in rows)
    assert not any("lsb_release" in str(row["detail"].get("argv")) for row in rows)
    assert not any(str(row["detail"].get("dest", "")).startswith("127.") for row in rows)
    assert all(row["evidence"]["layer"] == "strace" for row in rows)
    assert not any(row["detail"].get("path", "").endswith("libc.so.6") for row in rows)
    assert kinds


@pytest.mark.skipif(not bwrap_ok or not strace_ok, reason="strace inside bwrap unavailable")
def test_libc_open_of_canary_is_visible_to_strace(tmp_path):
    result = run_package(
        str(DATA / "native_open"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=60,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    for row in rows:
        validate("raw_event", row)
    assert result["run_meta"]["coverage"]["strace_layer"] is True
    assert "strace layer not active" not in " ".join(result["run_meta"]["coverage"]["not_observed"])
    hits = [
        row for row in rows
        if row.get("evidence", {}).get("layer") == "strace" and "id_rsa" in str(row.get("detail", {}).get("path", ""))
    ]
    assert hits
    assert any("ssh_key" in row.get("canary_match", []) for row in hits)
