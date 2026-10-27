"""Dev D. End-to-end through the real CLI (fixture runner => deterministic, no sandbox needed)."""
import json
import socket
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from trustlens.contracts import ROOT, validate

CASES = [
    ("malicious/evil_slug", 20),
    ("malicious/delayed_slug", 20),
    ("clean/clean_slug", 0),
    ("clean/rest_wrapper", 0),
]


@pytest.mark.parametrize("rel,code", CASES)
def test_scan_exit_codes_and_artifacts(rel, code, tmp_path):
    out = tmp_path / "o"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "scan",
            str(ROOT / "bench/packages" / rel),
            "--runner",
            "fixture",
            "--offline",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == code, r.stdout + r.stderr
    v = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    validate("verdict", v)
    validate("claims", json.loads((out / "claims.json").read_text(encoding="utf-8")))
    validate("fingerprint", json.loads((out / "fingerprint.json").read_text(encoding="utf-8")))

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<!doctype html" in html.lower()
    # strictly offline, self-contained: no remote scripts or stylesheets
    assert not any(t in html for t in ("<script src", "<link ", "src='http", 'src="http'))


def test_html_escapes_hostile_strings(tmp_path):
    from trustlens.report import render_html

    v = json.loads((ROOT / "schemas/examples/evil_slug/verdict.json").read_text(encoding="utf-8"))
    v["package"]["name"] = "<script>alert(1)</script>"
    v["summary"] = "<img src=x onerror=alert(1)>"
    html = render_html(v, {}, {})
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_determinism(tmp_path):
    """Determinism check: two runs of the same fixture produce identical verdict.json."""
    from trustlens.cli import scan

    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    pkg = str(ROOT / "bench/packages/clean/clean_slug")

    r1 = scan(pkg, str(out1), runner="fixture", offline=True)
    r2 = scan(pkg, str(out2), runner="fixture", offline=True)

    v1_text = (out1 / "verdict.json").read_text(encoding="utf-8")
    v2_text = (out2 / "verdict.json").read_text(encoding="utf-8")
    assert v1_text == v2_text
    assert r1["verdict"] == r2["verdict"]


def test_offline_mode_no_sockets(monkeypatch, tmp_path):
    """Verify that --offline scan performs zero external network calls."""
    from trustlens.cli import scan

    def forbidden_socket(*args, **kwargs):
        raise AssertionError("Network socket opened during offline scan!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    out = tmp_path / "offline_check"
    r = scan(str(ROOT / "bench/packages/clean/rest_wrapper"), str(out), runner="fixture", offline=True)
    assert r["verdict"]["action"] == "PASS"


def test_scan_wheel_archive(tmp_path):
    """Test safe extraction and scanning of wheel/zip package archives."""
    from trustlens.cli import scan

    # Create a synthetic zip archive from clean_slug
    archive_path = tmp_path / "clean_slug-0.1-py3-none-any.whl"
    src_dir = ROOT / "bench/packages/clean/clean_slug"

    with zipfile.ZipFile(archive_path, "w") as zf:
        for f in src_dir.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=f.relative_to(src_dir))

    out = tmp_path / "wheel_out"
    r = scan(str(archive_path), str(out), runner="fixture", offline=True)
    assert r["verdict"]["action"] == "PASS"
    validate("verdict", r["verdict"])


def test_scan_tar_archive(tmp_path):
    """Test safe extraction and scanning of sdist tarball archives."""
    from trustlens.cli import scan

    archive_path = tmp_path / "clean_slug-0.1.tar.gz"
    src_dir = ROOT / "bench/packages/clean/clean_slug"

    with tarfile.open(archive_path, "w:gz") as tf:
        for f in src_dir.rglob("*"):
            if f.is_file():
                tf.add(f, arcname=str(Path("clean_slug-0.1") / f.relative_to(src_dir)))

    out = tmp_path / "tar_out"
    r = scan(str(archive_path), str(out), runner="fixture", offline=True)
    assert r["verdict"]["action"] == "PASS"


def test_scan_requirements_txt(tmp_path):
    """Test scanning local dependencies specified in a requirements.txt file."""
    req_file = tmp_path / "requirements.txt"
    rel_clean = (ROOT / "bench/packages/clean/clean_slug").as_posix()
    req_file.write_text(f"-e {rel_clean}\n", encoding="utf-8")

    out = tmp_path / "req_out"
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(req_file), "--runner", "fixture", "--offline", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_friendly_errors_exit_2(tmp_path):
    """Missing path or invalid package must produce clear error and exit code 2."""
    # 1. Nonexistent path
    r_missing = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(tmp_path / "does_not_exist"), "--runner", "fixture"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r_missing.returncode == 2
    assert "does not exist" in r_missing.stderr

    # 2. Directory with no python files or package markers
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    r_invalid = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(empty_dir), "--runner", "fixture"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r_invalid.returncode == 2
    assert "not a valid Python package" in r_invalid.stderr


def test_check_env_command():
    """Verify check-env subcommand executes and emits valid JSON."""
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "check-env"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    # Return code is 0 (if bwrap_ok) or 2 (if bwrap not available)
    assert r.returncode in (0, 2)
    meta = json.loads(r.stdout)
    assert "bwrap_ok" in meta


def test_sarif_format_and_artifact(tmp_path):
    """Verify SARIF 2.1.0 output with --format sarif and report.sarif creation."""
    out = tmp_path / "sarif_out"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "scan",
            str(ROOT / "bench/packages/malicious/evil_slug"),
            "--runner",
            "fixture",
            "--format",
            "sarif",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 20
    sarif_file = out / "report.sarif"
    assert sarif_file.exists()
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "TrustLens AI"
    assert len(data["runs"][0]["results"]) >= 1


def test_compare_demo_command(tmp_path):
    """Verify compare-demo subcommand produces valid side-by-side HTML."""
    comp_file = tmp_path / "comp.html"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "compare-demo",
            "--runner",
            "fixture",
            "--out",
            str(comp_file),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert comp_file.exists()
    content = comp_file.read_text(encoding="utf-8")
    assert "Side-by-Side Verification" in content
    assert "rest-wrapper" in content or "rest_wrapper" in content
    assert "evil-slug" in content or "evil_slug" in content

