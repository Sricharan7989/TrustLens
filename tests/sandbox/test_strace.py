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


# strace -f splits a syscall when another traced process runs at the same moment.
# Shape copied from a real `strace -f` log of the baseline pipeline under CPU load.
SPLIT_BASE = """\
1409  execve("/bin/sh", ["/bin/sh", "-c", "printf %s x | tr ..."], 0x7ffd /* 9 vars */) = 0
1409  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 1410
1410  execve("/usr/bin/tr", ["tr", "[:lower:]", "[:upper:]"], 0x55f4 /* 9 vars */ <unfinished ...>
1411  execve("/usr/bin/cut", ["cut", "-c1"], 0x55f5 /* 9 vars */) = 0
1410  <... execve resumed>)             = 0
1412  openat(AT_FDCWD, "/w/home/.aws/credentials", O_RDONLY <unfinished ...>
1413  connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.9")}, 16 <unfinished ...>
1412  <... openat resumed>)             = 4
1413  <... connect resumed>)            = -1 ENETUNREACH (Network is unreachable)
"""


def test_baseline_keeps_helper_exec_split_by_strace():
    keys = baseline_keys(SPLIT_BASE)
    assert "execargv:" + "\0".join(["/usr/bin/tr", "tr", "[:lower:]", "[:upper:]"]) in keys
    assert "execargv:" + "\0".join(["/usr/bin/cut", "cut", "-c1"]) in keys


def test_split_helper_exec_is_subtracted_not_reported_as_spawn():
    """The flake: a baseline `tr` split by strace leaked into package runs as proc.spawn."""
    baseline = baseline_keys(SPLIT_BASE)
    run = '7 execve("/usr/bin/tr", ["tr", "[:lower:]", "[:upper:]"], 0x1 /* 9 vars */) = 0\n'
    rows = parse_strace(
        run, baseline, phase="install", trigger="install", profile="ci", variant="default",
        file_canaries=[], match_ids=lambda text: [],
    )
    assert not any(row["kind"] == "proc.spawn" for row in rows)


def test_split_package_syscalls_are_still_reported():
    """Splits on the package side used to drop real evidence (canary reads, connects)."""
    rows = parse_strace(
        SPLIT_BASE, set(), phase="install", trigger="install", profile="ci", variant="default",
        file_canaries=[(".aws/credentials", "aws_creds")], match_ids=lambda text: [],
    )
    reads = [row for row in rows if row["kind"] == "file.read"]
    assert reads and reads[0]["detail"]["path"] == "/w/home/.aws/credentials"
    assert reads[0]["canary_match"] == ["aws_creds"]
    assert any(row["kind"] == "net.connect" and row["detail"]["dest"] == "198.51.100.9:443" for row in rows)
    assert any(row["kind"] == "proc.spawn" and row["detail"]["argv"] == ["tr", "[:lower:]", "[:upper:]"] for row in rows)


def test_stitch_ignores_orphan_and_mismatched_resumes():
    from trustlens.sandbox.strace_parse import stitch_lines

    text = (
        '5 <... execve resumed>) = 0\n'
        '6 openat(AT_FDCWD, "/x", O_RDONLY <unfinished ...>\n'
        '6 <... connect resumed>) = 0\n'
        '8 execve("/bin/echo", ["echo"], 0x1) = 0\n'
    )
    assert stitch_lines(text) == ['8 execve("/bin/echo", ["echo"], 0x1) = 0']


def test_stitch_on_real_strace_log(tmp_path):
    """Run the baseline pipeline under the host strace (when allowed) and check stitching is lossless."""
    import shutil
    import subprocess

    strace = shutil.which("strace")
    if not strace:
        pytest.skip("strace not installed")
    log = tmp_path / "b.log"
    cmd = "printf %s x | tr '[:lower:]' '[:upper:]' >/dev/null; printf %s x | cut -c1 >/dev/null"
    proc = subprocess.run([strace, "-f", "-qq", "-e", "trace=execve", "-o", str(log), "/bin/sh", "-c", cmd],
                          capture_output=True, timeout=30)
    if proc.returncode != 0 or not log.exists():
        pytest.skip("ptrace not permitted here")
    keys = baseline_keys(log.read_text())
    assert any(k.startswith("execargv:/usr/bin/tr\0") or k.startswith("execargv:/bin/tr\0") for k in keys)
    assert any(k.startswith("execargv:/usr/bin/cut\0") or k.startswith("execargv:/bin/cut\0") for k in keys)
