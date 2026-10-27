"""Dev D. End-to-end through the real CLI (fixture runner => deterministic, no sandbox needed)."""
import json
import re
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


def test_diff_subcommand(tmp_path):
    """Verify diff subcommand compares two package versions and highlights changes (D13)."""
    diff_file = tmp_path / "diff.html"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "diff",
            str(ROOT / "bench/packages/clean/clean_slug"),
            str(ROOT / "bench/packages/malicious/evil_slug"),
            "--runner",
            "fixture",
            "--out",
            str(diff_file),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 20
    assert diff_file.exists()
    html = diff_file.read_text(encoding="utf-8")
    assert "Package Behavioral Diff" in html
    assert "Verdict Shift" in html
    assert "Newly Introduced Capabilities" in html


def test_scan_compare_flag(tmp_path):
    """Verify scan --compare invokes baseline adapters (D11)."""
    out = tmp_path / "comp_flag"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "scan",
            str(ROOT / "bench/packages/clean/clean_slug"),
            "--runner",
            "fixture",
            "--compare",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert "BASELINE COMPARISON" in r.stdout
    assert "GuardDog 3.2" in r.stdout
    assert "PipCanary 0.1" in r.stdout


def test_unrecorded_package_dir_exit_10(tmp_path):
    """(a) Package dir with a .py and README and no recording exits 10."""
    pkg = tmp_path / "unrecorded_pkg"
    pkg.mkdir()
    (pkg / "module.py").write_text("def run(): pass\n", encoding="utf-8")
    (pkg / "README.md").write_text("# Unrecorded\nA simple package.\n", encoding="utf-8")

    out = tmp_path / "out_unrec"
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(pkg), "--runner", "fixture", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 10
    v = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    assert v["action"] == "REVIEW"
    assert v["verdict"] == "INCONCLUSIVE"


def test_synthetic_pth_startup_exit_20(tmp_path):
    """(b) _synthetic_pth_startup expecting exit 20 and rule startup_hook."""
    pkg = tmp_path / "_synthetic_pth_startup"
    pkg.mkdir()
    (pkg / "setup.py").write_text("from setuptools import setup\nsetup(name='zz-helper', version='1.0')\n", encoding="utf-8")
    (pkg / "README.md").write_text("# zz-helper\nstring helper\n", encoding="utf-8")

    out = tmp_path / "out_pth"
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(pkg), "--runner", "fixture", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 20
    v = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    rules = [f.get("rule") for f in v.get("findings", [])]
    assert "startup_hook" in rules


def test_hostile_package_name_sanitized(tmp_path):
    """(e) Package whose setup.py name contains \\x1b[31mPWN\\x1b[0m and <script>alert(1)</script>.

    stdout has no ESC and no '<script>'. report.html keeps the escaped tag.
    claims.json, verdict.json, fingerprint.json, and report.json drop the tag and the CSI sequence.
    """
    pkg = tmp_path / "hostile_pkg"
    pkg.mkdir()
    (pkg / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='\x1b[31mPWN\x1b[0m<script>alert(1)</script>', version='1.0')\n",
        encoding="utf-8",
    )
    (pkg / "README.md").write_text("# Hostile Package\nToken: TLCANARYSECRET12345\n", encoding="utf-8")

    out = tmp_path / "out_hostile"
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(pkg), "--runner", "fixture", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    # Stdout must have no raw ANSI escapes and no literal '<script>'
    assert "\x1b" not in r.stdout
    assert "<script>" not in r.stdout
    assert "PWNalert(1)" in r.stdout

    # report.html must have the escaped script, no TLCANARY, and no raw ESC/CSI byte
    html_bytes = (out / "report.html").read_bytes()
    html = html_bytes.decode("utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "TLCANARY" not in html
    assert b"\x1b" not in html_bytes

    for name in ("claims.json", "verdict.json", "fingerprint.json", "report.json"):
        body = (out / name).read_text(encoding="utf-8")
        assert "<script>" not in body, name
        assert "\\u001b" not in body, name
        assert "\x1b" not in body, name
        assert "PWNalert(1)" in body, name
    validate("claims", json.loads((out / "claims.json").read_text(encoding="utf-8")))
    validate("verdict", json.loads((out / "verdict.json").read_text(encoding="utf-8")))
    validate("fingerprint", json.loads((out / "fingerprint.json").read_text(encoding="utf-8")))


def test_redact_text_drops_html_tags_after_controls():
    """strip_controls leaves tags. redact_text drops active HTML afterwards and keeps canary ids."""
    from trustlens.report.redact import redact_document, redact_text, strip_controls

    raw = "\x1b[31mPWN\x1b[0m<script>alert(1)</script>"
    stripped = strip_controls(raw)
    assert stripped == "PWN<script>alert(1)</script>"
    assert redact_text(raw) == "PWNalert(1)"
    assert redact_text("ssh_key") == "ssh_key"
    # Inert markup is kept (JSON is not rendered); only active HTML is dropped.
    assert redact_text("<code>ssh_key</code>") == "<code>ssh_key</code>"
    assert redact_text("<iframe src=//e></iframe>ssh_key") == "ssh_key"
    doc = redact_document({"package": {"name": raw}, "note": "id ssh_key"})
    assert doc["package"]["name"] == "PWNalert(1)"
    assert doc["note"] == "id ssh_key"
    assert "<script>" not in json.dumps(doc)
    assert "\\u001b" not in json.dumps(doc)


def _assert_canary_report_clean(html: str, text: str, sarif: str) -> None:
    """Rendered reports must not leak canary token bytes or exfil URLs."""
    for label, body in (("html", html), ("text", text), ("sarif", sarif)):
        assert "TLCANARY" not in body, label
        assert "http://" not in body, label


def test_canary_urls_redacted_evil_slug_and_shapes(tmp_path):
    """evil_slug and canary_shapes html/text/sarif drop TLCANARY and http:// when canary bytes were seen.

    ssh_key (a canary id, not a token) stays in the evil_slug report.
    """
    out = tmp_path / "evil"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "scan",
            str(ROOT / "bench/packages/malicious/evil_slug"),
            "--runner",
            "fixture",
            "--offline",
            "--format",
            "text",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 20, r.stdout + r.stderr
    html = (out / "report.html").read_text(encoding="utf-8")
    sarif = (out / "report.sarif").read_text(encoding="utf-8")
    _assert_canary_report_clean(html, r.stdout, sarif)
    assert "ssh_key" in html
    assert "ssh_key" in sarif
    assert "[url redacted]" in html
    assert "[url redacted]" in sarif

    from trustlens.claims import extract_claims, read_package_info
    from trustlens.engine import evaluate
    from trustlens.fingerprint import build_fingerprint
    from trustlens.report import render_html, render_sarif, render_text

    pkg = ROOT / "tests/sandbox/data/canary_shapes"
    recorded = ROOT / "tests/sandbox/recorded/canary_shapes"
    meta = json.loads((recorded / "run_meta.json").read_text(encoding="utf-8"))
    claims = extract_claims(str(pkg))
    fp = build_fingerprint(str(recorded / "raw_events.jsonl"), meta, read_package_info(str(pkg)))
    assert any(ev.get("detail", {}).get("canary_in_bytes") for ev in fp["events"])
    verdict = evaluate(fp, claims)
    shape_html = render_html(verdict, fp, claims)
    shape_text = render_text(verdict)
    shape_sarif = render_sarif(verdict, fp, claims)
    _assert_canary_report_clean(shape_html, shape_text, shape_sarif)
    assert "aws_secret_env" in shape_html
    assert "evil.invalid" not in shape_html
    assert "krgegqkoifjfsqkxknjukq2sivkektswgrrggytdha4wgmzxmm4a" not in shape_html
    for title in re.findall(r"title='([^']*)'", shape_html):
        if "canary_in_bytes" in title:
            assert "198.51.100.30" not in title
            assert "evil.invalid" not in title
            assert "http://" not in title


def _assert_redacted_json(text: str, *, label: str, keep: str | None = None) -> None:
    """Written JSON must not carry canary token bytes or canary exfil URLs."""
    assert "TLCANARY" not in text, label
    assert "http://198.51.100" not in text, label
    if keep is not None:
        assert keep in text, label


def test_json_artifacts_redact_canary_copies(tmp_path):
    """verdict.json, fingerprint.json, and report.json are redacted copies. scan() returns the raw objects."""
    from trustlens.cli import scan

    out = tmp_path / "evil"
    result = scan(str(ROOT / "bench/packages/malicious/evil_slug"), str(out), runner="fixture", offline=True)
    assert "TLCANARY" in json.dumps(result["verdict"])
    assert "TLCANARY" in json.dumps(result["fingerprint"])
    assert "http://198.51.100" in json.dumps(result["verdict"])

    for name in ("verdict.json", "fingerprint.json", "report.json", "report.html", "report.sarif"):
        body = (out / name).read_text(encoding="utf-8")
        _assert_redacted_json(body, label=name, keep="ssh_key")
    validate("verdict", json.loads((out / "verdict.json").read_text(encoding="utf-8")))
    validate("fingerprint", json.loads((out / "fingerprint.json").read_text(encoding="utf-8")))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["verdict"]["action"] == result["verdict"]["action"]
    assert "TLCANARY" not in json.dumps(report)

    cli = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlens",
            "scan",
            str(ROOT / "bench/packages/malicious/evil_slug"),
            "--runner",
            "fixture",
            "--offline",
            "--format",
            "json",
            "--out",
            str(tmp_path / "evil-stdout"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert cli.returncode == 20, cli.stderr
    _assert_redacted_json(cli.stdout, label="stdout json", keep="ssh_key")


def test_canary_shapes_json_redacts_flagged_urls():
    """canary_shapes report JSON drops token bytes and http://198.51.100 where canary_in_bytes is set."""
    from trustlens.claims import extract_claims, read_package_info
    from trustlens.engine import evaluate
    from trustlens.fingerprint import build_fingerprint
    from trustlens.report import render_json
    from trustlens.report.redact import redact_document

    pkg = ROOT / "tests/sandbox/data/canary_shapes"
    recorded = ROOT / "tests/sandbox/recorded/canary_shapes"
    meta = json.loads((recorded / "run_meta.json").read_text(encoding="utf-8"))
    claims = extract_claims(str(pkg))
    fp = build_fingerprint(str(recorded / "raw_events.jsonl"), meta, read_package_info(str(pkg)))
    verdict = evaluate(fp, claims)
    assert "TLCANARY" in json.dumps(fp)
    report = render_json(verdict, fp, claims)
    redacted_fp = json.dumps(redact_document(fp))
    redacted_verdict = json.dumps(redact_document(verdict))
    assert "TLCANARY" in json.dumps(fp)
    assert "TLCANARY" in json.dumps(verdict)
    for label, body in (("report.json", report), ("fingerprint", redacted_fp), ("verdict", redacted_verdict)):
        _assert_redacted_json(body, label=label, keep="aws_secret_env")
    validate("verdict", json.loads(redacted_verdict))
    validate("fingerprint", json.loads(redacted_fp))


def test_unflagged_destination_url_is_kept():
    """cli_toy's http destination has no canary_in_bytes, so the URL stays. Catalog tokens still become [canary]."""
    from trustlens.claims import extract_claims, read_package_info
    from trustlens.engine import evaluate
    from trustlens.fingerprint import build_fingerprint
    from trustlens.report.redact import redact_document

    pkg = ROOT / "tests/sandbox/data/cli_toy"
    recorded = ROOT / "tests/sandbox/recorded/cli_toy"
    meta = json.loads((recorded / "run_meta.json").read_text(encoding="utf-8"))
    claims = extract_claims(str(pkg))
    fp = build_fingerprint(str(recorded / "raw_events.jsonl"), meta, read_package_info(str(pkg)))
    verdict = evaluate(fp, claims)
    assert any(
        ev.get("detail", {}).get("url") == "http://198.51.100.11/cli" and not ev.get("detail", {}).get("canary_in_bytes")
        for ev in fp["events"]
    )
    redacted = redact_document({"verdict": verdict, "fingerprint": fp})
    assert "TLCANARY" in json.dumps(fp)
    body = json.dumps(redacted)
    assert "TLCANARY" not in body
    assert "http://198.51.100.11/cli" in body
    assert "[canary]" in body


def test_c1_csi_and_osc_are_stripped():
    """A real C1 CSI and an OSC sequence are removed, not left as a trailing fragment."""
    from trustlens.report.html import esc
    from trustlens.report.redact import strip_controls

    csi = strip_controls("\x9b31mPWN")
    osc = strip_controls("before\x1b]0;evil\x07after")
    assert csi == "PWN"
    assert "31m" not in csi
    assert osc == "beforeafter"
    assert "]0;evil" not in osc
    assert strip_controls("\x1b[31mOK\x1b[0m") == "OK"
    html = esc("\x9b31m<script>\x1b]0;evil\x07")
    assert "31m" not in html
    assert "]0;evil" not in html
    assert "\x1b" not in html
    assert "\x9b" not in html
    assert "&lt;script&gt;" in html


def test_zip_file_member_shadowing_directory_exits_2(tmp_path):
    """A zip member 'link' plus 'link/owned' is a usage error (exit 2), not a traceback."""
    archive = tmp_path / "bad-link.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("link", b"not-a-directory")
        zf.writestr("link/owned", b"child")
    r = subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", str(archive), "--runner", "fixture", "--out", str(tmp_path / "out")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 2
    assert "Traceback" not in r.stderr
    assert "trustlens: error:" in r.stderr
    assert "cannot extract" in r.stderr


def test_no_color_emits_no_ansi(monkeypatch):
    """(f) NO_COLOR=1 emits no \x1b."""
    import os

    from trustlens.report.text import render_text

    monkeypatch.setenv("NO_COLOR", "1")
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    assert not use_color
    v = {"action": "BLOCK", "verdict": "MALICIOUS", "package": {"name": "test", "version": "1.0"}}
    txt = render_text(v, color=use_color)
    assert "\x1b" not in txt


def test_no_color_on_pty():
    """(f) NO_COLOR=1 on a pty emits no \x1b when pty is available (POSIX)."""
    import os

    try:
        import pty
    except ImportError:
        pytest.skip("pty is only available on POSIX systems")

    master, slave = pty.openpty()
    try:
        env = dict(os.environ, NO_COLOR="1")
        proc = subprocess.run(
            [sys.executable, "-m", "trustlens", "scan", str(ROOT / "bench/packages/clean/clean_slug"), "--runner", "fixture"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            timeout=30,
        )
        assert proc.returncode == 0
        os.close(slave)
        out = os.read(master, 10240).decode("utf-8", errors="ignore")
        assert "\x1b" not in out
    finally:
        os.close(master)



def test_redact_text_keeps_angle_bracket_evidence():
    """Frame names and code comparisons are evidence, not markup. Only active HTML is dropped."""
    from trustlens.report.redact import redact_text

    for keep in ('File "<string>", line 1', "<module>", "if a<b and c>d: run()", "List<String> x", "name <b>bold</b>"):
        assert redact_text(keep) == keep
    for raw, want in (
        ("<script>alert(1)</script>", "alert(1)"),
        ("<SCRIPT >x</script >", "x"),
        ("<img src=x onerror=alert(1)>", ""),
        ("<svg/onload=alert(1)>", ""),
        ('<a href="javascript:alert(1)">x</a>', "x</a>"),
    ):
        assert redact_text(raw) == want


def test_decoded_exec_report_keeps_string_frame(tmp_path):
    """delayed_slug's evidence names the <string> frame; JSON outputs must keep it."""
    out = tmp_path / "r"
    subprocess.run(
        [sys.executable, "-m", "trustlens", "scan", "bench/packages/malicious/delayed_slug",
         "--runner", "fixture", "--offline", "--out", str(out), "--format", "text"],
        capture_output=True, timeout=120,
    )
    assert "<string>" in (out / "verdict.json").read_text(encoding="utf-8")
    assert "<string>" in (out / "fingerprint.json").read_text(encoding="utf-8")


def test_scan_zip_with_same_name_package_folder(tmp_path):
    """Regression: evil_slug/evil_slug/__init__.py in a zip crashed with 'Destination path already exists'."""
    from trustlens.cli import scan

    archive_path = tmp_path / "evil_slug.zip"
    src_dir = ROOT / "bench/packages/malicious/evil_slug"
    with zipfile.ZipFile(archive_path, "w") as zf:
        for f in src_dir.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=str(Path("evil_slug") / f.relative_to(src_dir)))
    r = scan(str(archive_path), str(tmp_path / "zip_out"), runner="fixture", offline=True)
    assert r["verdict"]["package"]["name"] == "evil-slug"
    assert r["verdict"]["action"] == "BLOCK"


def test_installed_layout_uses_bundled_schemas(tmp_path):
    """A pip install has no repo schemas/: contracts must fall back to the bundled package data."""
    import importlib
    import shutil

    import trustlens.contracts as contracts

    fake_root = tmp_path / "site-packages"
    shutil.copytree(ROOT / "trustlens", fake_root / "trustlens", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "schemas", fake_root / "trustlens" / "_schemas", ignore=shutil.ignore_patterns("examples"))
    (fake_root / "trustlens" / "_calibration").mkdir()
    shutil.copy2(ROOT / "bench" / "calibration" / "noise_whitelist.yaml", fake_root / "trustlens" / "_calibration")
    spec = importlib.util.spec_from_file_location("installed_contracts", fake_root / "trustlens" / "contracts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.IN_REPO is False
    assert mod.SCHEMAS == (fake_root / "trustlens" / "_schemas").resolve()
    assert mod.CALIBRATION_WHITELIST.is_file()
    assert "capabilities" in mod.load_capabilities()
    assert mod.OUTPUT_ROOT == Path.cwd()
    assert contracts.IN_REPO is True


def test_webui_lists_every_bench_package():
    """The picker offers all bench packages, not a hard-coded four."""
    import yaml

    from trustlens.webui.server import bench_packages

    labels = yaml.safe_load((ROOT / "bench" / "labels.yaml").read_text())["packages"]
    listed = {p["path"] for p in bench_packages()}
    assert listed == {p["path"] for p in labels}


def test_webui_page_has_no_default_evil_slug_scan():
    """Regression: the page auto-scanned evil_slug on load and kept that report on screen when a later scan
    was slow or failed, so every package seemed to show the evil-slug report."""
    from trustlens.webui.server import HTML_PAGE

    assert "runScan('bench/packages/malicious/evil_slug')" not in HTML_PAGE
    assert 'value="bench/packages/malicious/evil_slug"' not in HTML_PAGE
    assert "seq !== scanSeq" in HTML_PAGE  # late answers from an earlier click are dropped
    assert "showPlaceholder('Scanning '" in HTML_PAGE  # old report cleared as soon as a scan starts
    assert "showPlaceholder('No report for '" in HTML_PAGE  # errors replace the old report


@pytest.mark.parametrize("pkg", ["malicious/delayed_slug", "clean/clean_slug", "clean/rest_wrapper"])
def test_webui_scan_returns_report_of_requested_package(tmp_path, pkg):
    """Each scan returns the report of the package that was asked for."""
    import http.client
    import threading
    from http.server import ThreadingHTTPServer

    from trustlens.webui import server as srv

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.TrustLensWebHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=300)
        c.request("POST", "/api/scan", body=json.dumps({"package": f"bench/packages/{pkg}", "profiles": "dev,ci"}),
                  headers={"Content-Type": "application/json", "Host": "127.0.0.1"})
        data = json.loads(c.getresponse().read())
    finally:
        httpd.shutdown()
    name = pkg.split("/")[-1].replace("_", "-")
    assert data["verdict"]["package"]["name"] == name
    assert f"<title>TrustLens: {name}" in data["report_html"]
    assert "evil-slug" not in data["report_html"]
