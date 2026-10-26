"""Loopback sinkhole: hostname resolution stays inside the netns and a second stage can run."""
import struct
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl
from trustlens.sandbox import check_env, run_package
from trustlens.sandbox.agent.sinkhole import _dns_response

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


def _query(name: str, qtype: int) -> bytes:
    body = b""
    for label in name.split("."):
        body += bytes([len(label)]) + label.encode()
    body += b"\x00" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + body


def test_dns_answer_is_loopback_and_header_is_12_bytes():
    reply = _dns_response(_query("payload.invalid", 1))
    assert reply is not None
    assert len(reply) >= 12
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", reply[:12])
    assert tid == 0x1234
    assert flags & 0x8000  # QR
    assert (qd, an, ns, ar) == (1, 1, 0, 0)
    assert reply[-4:] == bytes((127, 0, 0, 1))
    aaaa = _dns_response(_query("payload.invalid", 28))
    assert aaaa is not None
    assert struct.unpack(">HHHHHH", aaaa[:12])[3] == 0


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_sinkhole_serves_second_stage(tmp_path):
    result = run_package(
        str(DATA / "sink_dropper"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=60,
    )
    meta = result["run_meta"]
    assert meta["run"]["network"] == "sinkhole"
    assert meta["coverage"]["network"] == "sinkhole"
    assert "loopback sinkhole not active" not in meta["coverage"]["not_observed"]
    rows = list(iter_jsonl(result["raw_events_path"]))
    assert any(row["kind"] == "net.dns" and "payload.invalid" in str(row["detail"]) for row in rows)
    executed = [row for row in rows if row["kind"] in {"dyn.exec", "dyn.compile"}]
    assert any("trustlens-sinkhole-marker" in str(row.get("detail")) for row in executed)
