"""Unit tests for coverage text, install diff, and the shell environment check."""
import subprocess

from trustlens.contracts import ROOT, validate
from trustlens.sandbox import check_env
from trustlens.sandbox.coverage import build_not_observed
from trustlens.sandbox.install_diff import console_scripts, diff_installed


def test_not_observed_lists_only_real_gaps():
    quiet = build_not_observed(
        triggers=["install", "fresh_startup", "call_all", "cli"],
        ran_triggers=["install", "fresh_startup", "call_all", "cli:tool"],
        variants=["default", "clock+30d"],
        strace_layer=True, sinkhole=True, clock_python_only=False,
        install_completed=True, install_requested=True, cli_found=True, failed_mods=[],
    )
    assert quiet == []
    gaps = build_not_observed(
        triggers=["install"], ran_triggers=["install"], variants=["default"],
        strace_layer=False, sinkhole=False, clock_python_only=False,
        install_completed=False, install_requested=True, cli_found=False, failed_mods=["evil: ImportError"],
    )
    text = " ".join(gaps)
    assert "strace layer not active" in text
    assert "clock variant not run" in text
    assert "loopback sinkhole not active" in text
    assert "fresh-interpreter startup not tested" in text
    assert "CLI entry points not run" in text
    assert "real pip install did not complete" in text
    assert "evil: ImportError" in text


def test_install_diff_emits_pth_and_entry_points(tmp_path):
    installed = tmp_path / "installed"
    (installed / "pth_toy").mkdir(parents=True)
    (installed / "pth_toy" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    (installed / "zz_helper.pth").write_text("# comment\nimport _zz_helper\n", encoding="utf-8")
    (installed / "_zz_helper.py").write_text("print('hi')\n", encoding="utf-8")
    (installed / "sitecustomize.py").write_text("print('site')\n", encoding="utf-8")
    dist = installed / "pth_toy-0.1.dist-info"
    dist.mkdir()
    (dist / "entry_points.txt").write_text("[console_scripts]\ntool=pth_toy:main\n", encoding="utf-8")
    (dist / "METADATA").write_text("Name: pth-toy\n", encoding="utf-8")
    events, files, scripts = diff_installed(installed, profile="dev", setup_text="setup(cmdclass={'bdist_wheel': BdistWheel})")
    assert ("tool", "pth_toy:main") in scripts
    assert any(event["kind"] == "startup.pth" and event["detail"]["line_text"] == "import _zz_helper" for event in events)
    assert any(event["kind"] == "startup.sitecustomize" for event in events)
    assert any(event["kind"] == "install.hook" and event["detail"].get("cmd") == "cmdclass" for event in events)
    assert any(event["kind"] == "file.new" and event["detail"]["path"] == "_zz_helper.py" for event in events)
    assert not any(event["kind"] == "file.new" and "dist-info" in event["detail"].get("path", "") for event in events)
    for event in events:
        validate("raw_event", event)
    assert "_zz_helper.py" in files
    assert console_scripts("[console_scripts]\na=b:c\n") == [("a", "b:c")]


def test_check_env_script_exit_matches_live_safe():
    result = subprocess.run(["bash", str(ROOT / "scripts" / "check_env.sh")], cwd=ROOT, capture_output=True, text=True, timeout=60)
    env = check_env()
    if env["live_safe"]:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "network really blocked" in result.stdout
        assert "YES" in result.stdout
    else:
        assert result.returncode != 0


def test_fixture_run_still_marked_stub(tmp_path):
    from trustlens.sandbox import run_package

    result = run_package(str(ROOT / "bench" / "packages" / "clean" / "clean_slug"), str(tmp_path), runner="fixture")
    assert result["run_meta"]["run"]["stub"] is True
    assert result["run_meta"]["run"]["sandbox"] == "fixture"
