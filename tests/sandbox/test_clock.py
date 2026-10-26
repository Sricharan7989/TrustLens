"""clock+30d variant. libfaketime when the .so is on the host, else the Python time patch."""
from pathlib import Path

import pytest

from trustlens.contracts import iter_jsonl
from trustlens.sandbox import check_env, run_package

DATA = Path(__file__).parent / "data"
bwrap_ok = check_env().get("bwrap_ok")


def _clock_net(rows, variant):
    return [
        row for row in rows
        if row["variant"] == variant and row["kind"].startswith("net.") and row["attributed_to"] == "pkg"
        and "198.51.100.40" in str(row.get("detail"))
    ]


@pytest.mark.skipif(not bwrap_ok, reason="bwrap rootless unavailable")
def test_clock_gate_fires_only_in_clock_variant(tmp_path):
    result = run_package(
        str(DATA / "clock_gate"), str(tmp_path), runner="live", profiles=("dev",),
        triggers=("call_all",), timeout_s=60,
    )
    rows = list(iter_jsonl(result["raw_events_path"]))
    assert "clock+30d" in result["run_meta"]["coverage"]["variants_run"]
    assert _clock_net(rows, "clock+30d")
    assert not _clock_net(rows, "default")
    assert all(row["variant"] == "clock+30d" for row in _clock_net(rows, "clock+30d"))
