"""Dev D. End-to-end through the real CLI (fixture runner => deterministic, no sandbox needed)."""
import json
import subprocess
import sys

import pytest

from trustlens.contracts import ROOT, validate

CASES = [("malicious/evil_slug", 20), ("malicious/delayed_slug", 20), ("clean/clean_slug", 0), ("clean/rest_wrapper", 0)]


@pytest.mark.parametrize("rel,code", CASES)
def test_scan_exit_codes_and_artifacts(rel, code, tmp_path):
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, "-m", "trustlens", "scan", str(ROOT / "bench/packages" / rel), "--runner", "fixture", "--offline", "--out", str(out)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == code, r.stdout + r.stderr
    validate("verdict", json.loads((out / "verdict.json").read_text()))
    html = (out / "report.html").read_text()
    assert "<!doctype html" in html.lower() and not any(t in html for t in ("<script src", "<link ", "src='http", 'src="http'))  # self-contained, no remote assets


def test_html_escapes_hostile_strings(tmp_path):
    from trustlens.report import render_html
    v = json.loads((ROOT / "schemas/examples/evil_slug/verdict.json").read_text())
    v["package"]["name"] = "<script>alert(1)</script>"
    v["summary"] = "<img src=x onerror=alert(1)>"
    assert "<script>alert(1)" not in render_html(v, {}, {})
