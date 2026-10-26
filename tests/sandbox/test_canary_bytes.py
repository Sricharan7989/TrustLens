"""Canary tokens matched in URLs, headers, bodies, DNS labels, socket.send, and argv."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl, validate
from trustlens.sandbox import check_env, run_package
from trustlens.sandbox.agent.canarymatch import match_ids, token_forms

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


def test_token_forms_include_base32():
    forms = token_forms("TLCANARYAWSSECRETENVabc123")
    assert forms[0] == "TLCANARYAWSSECRETENVabc123"
    assert any(form != forms[0] and form.isalnum() for form in forms)
    assert match_ids(forms[1] + ".evil.invalid", {"TLCANARYAWSSECRETENVabc123": "aws_secret_env"}) == ["aws_secret_env"]


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_five_exfil_shapes_match_canary(tmp_path):
    result = run_package(
        str(DATA / "canary_shapes"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=90,
    )
    rows = [row for row in iter_jsonl(result["raw_events_path"]) if row["attributed_to"] == "pkg"]
    for row in rows:
        validate("raw_event", row)

    def matched(kind_prefix: str, detail_has: str) -> bool:
        return any(
            row["kind"].startswith(kind_prefix) and detail_has in str(row["detail"]) and "aws_secret_env" in row.get("canary_match", [])
            for row in rows
        )

    assert matched("net.http", "198.51.100.30/c?d=")
    # urllib.request capitalizes header names before the audit event (X-Canary -> X-canary).
    assert any(
        row["kind"].startswith("net.http")
        and "x-canary" in str(row["detail"]).lower()
        and "aws_secret_env" in row.get("canary_match", [])
        for row in rows
    )
    assert any(row["kind"] == "net.http" and row["detail"].get("data_head") and "aws_secret_env" in row.get("canary_match", []) for row in rows)
    assert matched("net.dns", ".evil.invalid")
    assert matched("net.send", "")
    assert matched("proc.spawn", "curl")
