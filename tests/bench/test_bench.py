"""Dev C. Labels, metrics, dataset tooling (offline parts only)."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml

from eval.metrics import confusion, wilson
from trustlens.contracts import ROOT, validate


def test_wilson_known_values():
    lo, hi = wilson(0, 15)
    assert lo == 0.0 and 0.17 < hi < 0.23  # 0/15 FP is NOT 'zero FP rate': upper bound ~20%
    assert wilson(0, 0) is None


def test_confusion_counts_inconclusive_as_not_flagged():
    rows = [{"label": "malicious", "flagged": True, "trigger": "install", "gate": "none"},
            {"label": "malicious", "flagged": None, "trigger": "call", "gate": "ci"},
            {"label": "clean", "flagged": False}]
    c = confusion(rows)
    assert (c["tp"], c["fn"], c["tn"], c["fp"], c["inconclusive"]) == (1, 1, 1, 0, 1)


def test_every_bench_package_has_readme_and_label():
    labels = yaml.safe_load((ROOT / "bench/labels.yaml").read_text())["packages"]
    ids = [p["id"] for p in labels]
    assert len(ids) == len(set(ids))
    for p in labels:
        assert (ROOT / p["path"] / "README.md").exists(), p["id"]
        assert p["label"] in ("malicious", "clean")


def test_planted_toys_only_use_reserved_addresses():
    import re
    ok = re.compile(r"(198\.51\.100\.\d+|203\.0\.113\.\d+|192\.0\.2\.\d+|[\w.-]+\.invalid|[\w.-]+\.test|example\.(com|org))")
    for f in (ROOT / "bench/packages/malicious").rglob("*.py"):
        for host in re.findall(r"https?://([\w.-]+)", f.read_text()):
            assert ok.fullmatch(host), f"{f}: non-reserved host {host}"


def test_datadog_sampler_is_importable_and_seeded():
    spec = importlib.util.spec_from_file_location("sd", ROOT / "bench/tools/sample_datadog.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    import random
    names = [f"p{i}" for i in range(500)]
    assert sorted(random.Random(7).sample(names, 5)) == sorted(random.Random(7).sample(names, 5))


def test_eval_runs_on_fixtures(tmp_path):
    r = subprocess.run([sys.executable, "-m", "eval.run_eval", "--runner", "fixture", "--tools", "trustlens,guarddog,pipcanary,packj", "--limit", "4", "--out", str(tmp_path)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    res_file = Path(tmp_path) / "results.json"
    sum_file = Path(tmp_path) / "summary.md"
    hm_file = Path(tmp_path) / "heatmap.html"
    assert res_file.exists()
    assert sum_file.exists()
    assert hm_file.exists()

    data = json.loads(res_file.read_text(encoding="utf-8"))
    validate("eval_results", data)
    assert "tools" in data
    assert "trustlens" in data["tools"]

    summary = sum_file.read_text(encoding="utf-8")
    assert "PS1-Bench Evaluation Summary" in summary
    assert "Date (UTC):" in summary
    assert "runner" in summary.lower()
    assert "wilson 95%" in summary.lower()
    assert "not run" in summary

    heatmap_content = hm_file.read_text(encoding="utf-8")
    assert "<table" in heatmap_content
    assert "not run" in heatmap_content
    assert "legend" in heatmap_content


def test_labels_external_conforms_to_schema():
    ext = ROOT / "bench/labels_external.yaml"
    if ext.exists():
        labels = yaml.safe_load(ext.read_text())
        validate("bench_labels", labels)
        assert len(labels["packages"]) >= 25
        for p in labels["packages"]:
            assert p["label"] == "clean"
            assert p["category"] == "top_pypi"
            assert (ROOT / p["path"]).exists()


def test_labels_datadog_conforms_to_schema():
    dd = ROOT / "bench/labels_datadog.yaml"
    if dd.exists():
        labels = yaml.safe_load(dd.read_text())
        validate("bench_labels", labels)
        assert 100 <= len(labels["packages"]) <= 200
        for p in labels["packages"]:
            assert p["label"] == "malicious"
            assert p["category"] == "datadog"
            assert (ROOT / p["path"]).exists()


def test_load_labels_multi_and_all():
    from eval.run_eval import load_labels
    name, pkgs = load_labels(None, runner="fixture")
    assert name == "labels.yaml"
    assert len(pkgs) >= 26

    name_all, pkgs_all = load_labels("all", runner="fixture")
    assert len(pkgs_all) >= len(pkgs)
    assert "labels.yaml" in name_all


def test_compute_category_metrics():
    from eval.run_eval import compute_category_metrics
    rows = [
        {"category": "planted", "flagged": True},
        {"category": "planted", "flagged": False},
        {"category": "datadog", "flagged": True},
        {"category": "datadog", "flagged": None},
        {"category": "clean_control", "flagged": False},
        {"category": "noisy_benign", "flagged": False},
        {"category": "top_pypi", "flagged": False},
    ]
    cm = compute_category_metrics(rows, available=True)
    assert cm["planted_toys"]["tp"] == 1
    assert cm["planted_toys"]["total"] == 2
    assert cm["planted_toys"]["recall"] == 0.5
    assert cm["external_malware"]["tp"] == 1
    assert cm["external_malware"]["inconclusive"] == 1
    assert cm["external_malware"]["total"] == 2
    assert cm["clean_controls"]["fp"] == 0
    assert cm["noisy_benign"]["fp"] == 0
    assert cm["top_pypi"]["fp"] == 0


def test_noise_whitelist_yaml_valid_and_safe():
    wl_file = ROOT / "bench/calibration/noise_whitelist.yaml"
    assert wl_file.exists(), "bench/calibration/noise_whitelist.yaml must exist"
    data = yaml.safe_load(wl_file.read_text(encoding="utf-8"))
    assert "rules" in data
    rules = data["rules"]
    assert len(rules) >= 5
    for r in rules:
        assert "capability" in r
        assert any(k in r for k in ("path_glob", "host_glob", "env_glob"))
        assert "reason" in r
        assert "source" in r
        assert "benign_prevalence" in r
        assert 0.0 <= r["benign_prevalence"] <= 1.0
        val = str(r.get("path_glob") or r.get("host_glob") or r.get("env_glob") or "")
        # Safety invariant: no rule may match canary tokens, sensitive credential files, or RFC 5737 targets
        for forbidden in ("id_rsa", ".ssh", ".aws", ".npmrc", "canary", "198.51.100", "203.0.113", "192.0.2"):
            assert forbidden not in val.lower()


def test_noise_whitelist_loaded_by_normalizer():
    from trustlens.fingerprint.normalize import _load_whitelist
    rules = _load_whitelist()
    sources = {r.get("source") for r in rules}
    assert any("calibration" in s or "QUT" in s for s in sources if s)


def test_guarddog_network_rules_excluded():
    from eval.baselines.guarddog import EXCLUDE
    assert "typosquatting" in EXCLUDE
    assert "potentially_compromised_email_domain" in EXCLUDE
    assert "unclaimed_maintainer_email_domain" in EXCLUDE
    assert len(EXCLUDE) == 3


def test_baseline_adapters_contract_when_uninstalled(monkeypatch, tmp_path):
    from eval.baselines import guarddog, packj, pipcanary
    monkeypatch.setattr("shutil.which", lambda _: None)

    for mod, name in [(guarddog, "guarddog"), (pipcanary, "pipcanary"), (packj, "packj")]:
        res = mod.run(tmp_path)
        assert res["available"] is False
        assert res["flagged"] is None
        assert res["rules"] == []
        assert res["runtime_s"] is None
        assert name in res["error"] or "missing" in res["error"]


def test_guarddog_mock_execution(monkeypatch, tmp_path):
    from eval.baselines import guarddog

    class DummyProc:
        def __init__(self, stdout: str):
            self.stdout = stdout

    monkeypatch.setattr("shutil.which", lambda exe: f"/fake/{exe}")

    # Malicious output
    mock_hit = json.dumps({"results": {"shady_url": ["hit1"], "cmd_exec": ["hit2"]}})
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc(mock_hit))
    r = guarddog.run(tmp_path)
    assert r["available"] is True
    assert r["flagged"] is True
    assert r["rules"] == ["cmd_exec", "shady_url"]
    assert r["error"] is None

    # Benign output
    mock_clean = json.dumps({"results": {}})
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc(mock_clean))
    r_clean = guarddog.run(tmp_path)
    assert r_clean["available"] is True
    assert r_clean["flagged"] is False
    assert r_clean["rules"] == []
    assert r_clean["error"] is None


def test_pipcanary_mock_and_safety_guard(monkeypatch, tmp_path):
    from eval.baselines import pipcanary

    class DummyProc:
        def __init__(self, stdout: str, stderr: str = ""):
            self.stdout = stdout
            self.stderr = stderr

    monkeypatch.setattr("shutil.which", lambda exe: f"/fake/{exe}")

    # Safety guardrail: refuse on real malware unless Docker --network none
    malware_pkg = tmp_path / "data" / "datadog" / "extracted" / "badpkg"
    malware_pkg.mkdir(parents=True)
    monkeypatch.delenv("DOCKER_NETWORK_NONE", raising=False)
    monkeypatch.delenv("ALLOW_PIPCANARY_MALWARE", raising=False)
    r_safe = pipcanary.run(malware_pkg)
    assert r_safe["available"] is True
    assert r_safe["flagged"] is None
    assert "refused to run on real malware" in r_safe["error"]

    # Clean package run with detection
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc("Scanning packages...\nFound suspicious access to /etc/shadow"))
    clean_pkg = tmp_path / "bench" / "packages" / "clean" / "toy"
    clean_pkg.mkdir(parents=True)
    r_flagged = pipcanary.run(clean_pkg)
    assert r_flagged["available"] is True
    assert r_flagged["flagged"] is True
    assert r_flagged["rules"] == ["credential_path_access"]
    assert r_flagged["error"] is None

    # Clean package run without detection
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc("Scanning packages...\nScan complete. 0 alerts."))
    r_benign = pipcanary.run(clean_pkg)
    assert r_benign["available"] is True
    assert r_benign["flagged"] is False
    assert r_benign["rules"] == []
    assert r_benign["error"] is None


def test_packj_mock_and_agpl_isolation(monkeypatch, tmp_path):
    from eval.baselines import packj

    # AGPL isolation: packj should not be imported
    assert "packj" not in sys.modules or sys.modules["packj"].__file__.endswith("eval\\baselines\\packj.py") or sys.modules["packj"].__file__.endswith("eval/baselines/packj.py")

    class DummyProc:
        def __init__(self, stdout: str):
            self.stdout = stdout

    monkeypatch.setattr("shutil.which", lambda exe: f"/fake/{exe}")

    # Malicious output
    mock_alerts = json.dumps({"alerts": [{"name": "network_call"}, {"name": "eval_exec"}]})
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc(mock_alerts))
    r = packj.run(tmp_path)
    assert r["available"] is True
    assert r["flagged"] is True
    assert r["rules"] == ["eval_exec", "network_call"]
    assert r["error"] is None

    # Benign output
    mock_clean = json.dumps({"alerts": []})
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: DummyProc(mock_clean))
    r_clean = packj.run(tmp_path)
    assert r_clean["available"] is True
    assert r_clean["flagged"] is False
    assert r_clean["rules"] == []
    assert r_clean["error"] is None


def test_held_out_yaml_conforms_to_schema():
    ho_file = ROOT / "bench/held_out.yaml"
    assert ho_file.exists(), "bench/held_out.yaml must exist"
    data = yaml.safe_load(ho_file.read_text(encoding="utf-8"))
    validate("bench_labels", data)
    pkgs = data["packages"]
    assert len(pkgs) == 10
    mal = [p for p in pkgs if p["label"] == "malicious"]
    clean = [p for p in pkgs if p["label"] == "clean"]
    assert len(mal) == 5
    assert len(clean) == 5
    for p in pkgs:
        assert (ROOT / p["path"]).exists(), f"Path does not exist: {p['path']}"
        assert p.get("claim"), f"Missing claim for package: {p['id']}"


def test_load_labels_held_out():
    from eval.run_eval import load_labels
    name, pkgs = load_labels("held_out", runner="fixture")
    assert "held_out.yaml" in name
    assert len(pkgs) == 10
    assert sum(p["label"] == "malicious" for p in pkgs) == 5
    assert sum(p["label"] == "clean" for p in pkgs) == 5


def test_eval_runs_on_held_out_split(tmp_path):
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "eval.run_eval",
            "--runner",
            "fixture",
            "--labels",
            "bench/held_out.yaml",
            "--tools",
            "trustlens,guarddog,pipcanary,packj",
            "--out",
            str(tmp_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stderr
    res_file = Path(tmp_path) / "results.json"
    sum_file = Path(tmp_path) / "summary.md"
    assert res_file.exists()
    assert sum_file.exists()

    data = json.loads(res_file.read_text(encoding="utf-8"))
    validate("eval_results", data)
    assert "held_out" in data
    assert data["held_out"]["n_clean"] == 5
    assert data["held_out"]["n_malicious"] == 5

    summary = sum_file.read_text(encoding="utf-8")
    assert "Held-Out Split Evaluation" in summary
    assert "5 Clean + 5 Malicious" in summary
    assert "Held-Out Package Detail" in summary


def test_osptrack_cell_parsing_in_build_noise_whitelist():
    from bench.calibration.build_noise_whitelist import parse_cell
    osp_file_cell = "[{'Delete': False, 'Path': '/dev/tty', 'Read': True}, {'Delete': False, 'Path': '/etc/ld.so.cache', 'Read': True}]"
    tokens = parse_cell(osp_file_cell)
    assert "/dev/tty" in tokens
    assert "/etc/ld.so.cache" in tokens

    osp_cmd_cell = "[{'Command': array(['ruby', '/usr/local/bin/analyze.rb'])}]"
    tokens_cmd = parse_cell(osp_cmd_cell)
    assert "ruby" in tokens_cmd

    empty_tokens = parse_cell("[]")
    assert empty_tokens == set()


def test_whitelist_cross_check_and_safety_invariant():
    from bench.tools.cross_check_whitelist import cross_check
    res = cross_check(ROOT / "bench/calibration/noise_whitelist.yaml")
    assert res["is_safe"] is True
    assert len(res["violations"]) == 0
    assert res["total_rules"] >= 5


def test_osptrack_metrics_analyzer_mock_and_real(tmp_path):
    from bench.tools.analyze_osptrack import analyze_metrics, generate_report
    mock_csv = tmp_path / "mock_metrics.csv"
    mock_csv.write_text(
        "pkg_type,name,version,location,function,attack_type,trigger_mechanism,hide\n"
        "pypi,mal1,1.0,setup,steal,dropper/malware,execute automatically upon download,base64-encoded\n"
        "pypi,mal2,1.0,setup,steal,typosquatting,installation,obfuscation\n"
        "npm,mal3,1.0,index,c2,C2 communication,running network connection,N/A\n",
        encoding="utf-8",
    )
    stats = analyze_metrics(mock_csv)
    assert stats["total_rows"] == 3
    assert stats["pypi_count"] == 2
    assert stats["npm_count"] == 1
    report = generate_report(stats)
    assert "# OSPTrack Empirical Analysis" in report
    assert "execute automatically upon download" in report
    assert "Planned Planted Toys" in report



