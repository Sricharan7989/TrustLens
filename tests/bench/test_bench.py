"""Dev C. Labels, metrics, dataset tooling (offline parts only)."""
import io
import json
import random
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from eval.metrics import confusion, wilson
from trustlens.contracts import ROOT, validate


def test_wilson_known_values():
    lo, hi = wilson(0, 15)
    assert lo == 0.0 and 0.17 < hi < 0.23  # 0/15 FP is NOT 'zero FP rate': upper bound ~20%
    assert wilson(0, 0) is None


def test_confusion_counts_inconclusive_as_not_flagged():
    rows = [
        {"label": "malicious", "flagged": True, "trigger": "install", "gate": "none"},
        {"label": "malicious", "flagged": None, "trigger": "call", "gate": "ci"},
        {"label": "clean", "flagged": None},
    ]
    c = confusion(rows)
    assert (c["tp"], c["fn"], c["tn"], c["fp"], c["inconclusive"]) == (1, 0, 0, 0, 2)
    assert c["recall"] == 1.0
    assert c["fp_rate"] is None


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


def test_datadog_sampler_is_importable_and_seeded(monkeypatch, tmp_path):
    """Dry-run samples an injected manifest. urlopen is stubbed; git is not called."""
    from bench.tools import sample_datadog as sd

    manifest = {f"pkg{i:02d}": None for i in range(40)}
    manifest["partial"] = ["1.0.0"]
    payload = json.dumps(manifest).encode()
    calls: list[str] = []

    def fake_urlopen(url, timeout=60):
        calls.append(str(url))
        return io.BytesIO(payload)

    def forbid_subprocess(*_a, **_k):
        raise AssertionError("dry-run must not spawn git or any subprocess")

    monkeypatch.setattr(sd.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(sd.subprocess, "run", forbid_subprocess)
    manifest_txt = ROOT / "bench" / "datadog_sample.txt"
    original = manifest_txt.read_text(encoding="utf-8")
    dest = tmp_path / "datadog"
    try:
        assert sd.main(["--n", "5", "--seed", "7", "--dry-run", "--dest", str(dest)]) == 0
        first = json.loads((dest / "sample.json").read_text(encoding="utf-8"))
        assert sd.main(["--n", "5", "--seed", "7", "--dry-run", "--dest", str(dest)]) == 0
        second = json.loads((dest / "sample.json").read_text(encoding="utf-8"))
    finally:
        manifest_txt.write_text(original, encoding="utf-8")
    names = sorted(k for k, v in manifest.items() if v is None)
    expected = sorted(random.Random(7).sample(names, 5))
    assert first["packages"] == expected
    assert second["packages"] == expected
    assert calls and all("manifest.json" in url for url in calls)
    assert "partial" not in expected


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
    assert "decided cases only" in summary
    assert "not disguised as true negatives" not in summary
    assert "ROC AUC:** `1.0" not in summary
    assert "ROC AUC:** `1.0000" not in summary

    heatmap_content = hm_file.read_text(encoding="utf-8")
    assert "<table" in heatmap_content
    assert "not run" in heatmap_content
    assert "legend" in heatmap_content


def _skip_if_data_paths_absent(labels: dict) -> None:
    missing = [p["path"] for p in labels["packages"] if not (ROOT / p["path"]).exists()]
    if missing:
        pytest.skip(f"data/ paths absent ({len(missing)} packages)")


def test_labels_external_conforms_to_schema():
    ext = ROOT / "bench/labels_external.yaml"
    if not ext.exists():
        pytest.skip("bench/labels_external.yaml absent")
    labels = yaml.safe_load(ext.read_text())
    validate("bench_labels", labels)
    _skip_if_data_paths_absent(labels)
    assert len(labels["packages"]) >= 25
    for p in labels["packages"]:
        assert p["label"] == "clean"
        assert p["category"] == "top_pypi"
        assert (ROOT / p["path"]).exists()


def test_labels_datadog_conforms_to_schema():
    dd = ROOT / "bench/labels_datadog.yaml"
    if not dd.exists():
        pytest.skip("bench/labels_datadog.yaml absent")
    labels = yaml.safe_load(dd.read_text())
    validate("bench_labels", labels)
    _skip_if_data_paths_absent(labels)
    assert 100 <= len(labels["packages"]) <= 200
    for p in labels["packages"]:
        assert p["label"] == "malicious"
        assert p["category"] == "datadog"
        assert (ROOT / p["path"]).exists()
def test_clean_chosen_json_exists_and_valid():
    cc = ROOT / "bench/clean_chosen.json"
    assert cc.exists(), "bench/clean_chosen.json must exist"
    data = json.loads(cc.read_text(encoding="utf-8"))
    assert "packages" in data
    assert len(data["packages"]) == 30
    for p in data["packages"]:
        for key in ("name", "version", "filename", "size", "sha256"):
            assert key in p, f"Missing key {key} in clean_chosen package {p}"
        assert len(p["sha256"]) == 64, f"sha256 must be full 64 hex characters: {p['sha256']}"
        assert p["size"] > 0


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
    assert cm["external_malware"]["fn"] == 0
    assert cm["external_malware"]["inconclusive"] == 1
    assert cm["external_malware"]["total"] == 2
    assert cm["external_malware"]["recall"] == 1.0
    assert cm["clean_controls"]["fp"] == 0
    assert cm["noisy_benign"]["fp"] == 0
    assert cm["top_pypi"]["fp"] == 0


_BANNED_PROC_GLOBS = {
    "*python*",
    "*ld*",
    "*clear*",
    "*strace*",
    "*cc1*",
    "*pip3*",
    "*systemd-oomd*",
    "*ThreadPoolForeg*",
    "*cc1plus*",
}


def test_noise_whitelist_yaml_valid_and_safe():
    wl_file = ROOT / "bench/calibration/noise_whitelist.yaml"
    assert wl_file.exists(), "bench/calibration/noise_whitelist.yaml must exist"
    data = yaml.safe_load(wl_file.read_text(encoding="utf-8"))
    assert "rules" in data
    rules = data["rules"]
    assert len(rules) >= 3
    for r in rules:
        assert "capability" in r
        assert any(k in r for k in ("path_glob", "host_glob", "env_glob"))
        assert "reason" in r
        assert "source" in r
        glob = str(r.get("path_glob") or "")
        assert glob not in _BANNED_PROC_GLOBS
        if r.get("source") == "seed":
            assert "benign_prevalence" not in r
        else:
            assert "benign_prevalence" in r
            assert 0.0 <= r["benign_prevalence"] <= 1.0
        val = str(r.get("path_glob") or r.get("host_glob") or r.get("env_glob") or "")
        # Safety invariant: no rule may match canary tokens, sensitive credential files, or RFC 5737 targets
        for forbidden in ("id_rsa", ".ssh", ".aws", ".npmrc", "canary", "198.51.100", "203.0.113", "192.0.2"):
            assert forbidden not in val.lower()


def test_noise_whitelist_loaded_by_normalizer():
    from trustlens.fingerprint.normalize import _load_whitelist
    rules = _load_whitelist()
    globs = {str(r.get("host_glob") or r.get("env_glob") or r.get("path_glob") or "") for r in rules}
    assert "127.0.0.1" in globs
    assert "localhost" in globs
    assert "PYTEST_CURRENT_TEST" in globs
    assert "TOX_ENV_NAME" in globs
    assert "127.0.0.1*" not in globs
    assert "TEST_*" not in globs
    assert _BANNED_PROC_GLOBS.isdisjoint(globs)


def test_guarddog_network_rules_excluded():
    from eval.baselines.guarddog import EXCLUDE
    assert "typosquatting" in EXCLUDE
    assert "potentially_compromised_email_domain" in EXCLUDE
    assert "unclaimed_maintainer_email_domain" in EXCLUDE
    assert len(EXCLUDE) == 3


def test_baseline_adapters_contract_when_uninstalled(monkeypatch, tmp_path):
    from eval.baselines import guarddog, packj, pipcanary
    monkeypatch.setattr("shutil.which", lambda *_a, **_k: None)
    real_is_file = Path.is_file

    def _venv_lookup_missing(self):
        # setup-dev installs the binaries next to sys.executable and under .venv.
        if self.name in {"guarddog", "pipcanary", "packj", "guarddog.exe", "pipcanary.exe", "packj.exe"}:
            return False
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", _venv_lookup_missing)

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
    assert "reported slice" in summary
    assert "strictly isolated" not in summary
    assert "never used" not in summary
    assert "not disguised as true negatives" not in summary
    assert "decided cases only" in summary


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
    assert res["total_rules"] >= 3


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
    assert "95.2" not in report
    assert "81.1" not in report
    assert "4/10" not in report
    assert "27 PyPI" not in report
    assert "(42 packages)" not in report
    assert "283" not in report


def test_osptrack_analyzer_missing_csv_prints_not_computed(tmp_path, capsys):
    from bench.tools.analyze_osptrack import main
    missing = tmp_path / "no-such.csv"
    out = tmp_path / "out.md"
    assert main(["--csv", str(missing), "--out", str(out)]) == 0
    assert "not computed" in capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert "not computed" in text
    assert "95.2" not in text
    assert "81.1" not in text


def test_malregistry_sampler_is_importable_and_seeded(monkeypatch, capsys):
    from bench.tools import sample_malregistry as mr

    pkgs = [f"mal_{i:03d}" for i in range(50)]

    def fail_clone():
        raise AssertionError("ensure_mr_clone must not run on --dry-run")

    def forbid_subprocess(*_a, **_k):
        raise AssertionError("dry-run must not call git")

    monkeypatch.setattr(mr, "ensure_mr_clone", fail_clone)
    monkeypatch.setattr(mr, "list_available_packages", lambda: list(pkgs))
    monkeypatch.setattr(mr.subprocess, "run", forbid_subprocess)
    expected = sorted(random.Random(42).sample(pkgs, 5))
    assert mr.main(["--dry-run", "--n", "5", "--seed", "42"]) == 0
    first = capsys.readouterr().out
    assert mr.main(["--dry-run", "--n", "5", "--seed", "42"]) == 0
    second = capsys.readouterr().out
    assert first == second
    for name in expected:
        assert name in first


def test_labels_malregistry_conforms_to_schema():
    mr = ROOT / "bench/labels_malregistry.yaml"
    if not mr.exists():
        pytest.skip("bench/labels_malregistry.yaml absent")
    labels = yaml.safe_load(mr.read_text(encoding="utf-8"))
    validate("bench_labels", labels)
    _skip_if_data_paths_absent(labels)
    assert len(labels["packages"]) >= 1
    for p in labels["packages"]:
        assert p["label"] == "malicious"
        assert p["category"] == "malregistry"
        assert p["expected_verdict"] == "MALICIOUS-EVIDENT"
        assert (ROOT / p["path"]).exists()
        assert (ROOT / p["path"] / "README.md").exists() or any((ROOT / p["path"]).rglob("README.md"))


def test_load_labels_malregistry():
    from eval.run_eval import load_labels
    name, pkgs = load_labels("malregistry", runner="fixture")
    assert "labels_malregistry.yaml" in name
    assert len(pkgs) >= 1
    assert all(p["category"] == "malregistry" for p in pkgs)
    assert all(p["label"] == "malicious" for p in pkgs)


def test_data_malregistry_strictly_untracked_by_git():
    # pypi_malregistry has NO LICENSE: must never be committed
    proc = subprocess.run(
        ["git", "ls-files", "data/malregistry"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked = proc.stdout.strip()
    assert tracked == "", f"Forbidden: malregistry samples tracked in git: {tracked}"


def test_threshold_sweep_loads_weights_readonly():
    from eval.threshold_sweep import WEIGHTS_FILE, load_weights_readonly
    w = load_weights_readonly()
    assert isinstance(w, dict)
    assert w["suspicious_threshold"] == 4.0
    assert w["block_min_independent_signals"] == 2
    assert "strong_signal_classes" in w
    assert WEIGHTS_FILE.exists()


def test_threshold_sweep_roc_auc_math():
    from eval.threshold_sweep import compute_roc_auc
    # Caller-supplied corners are integrated. The function does not add them.
    assert compute_roc_auc([{"fpr": 0.0, "tpr": 0.0}, {"fpr": 1.0, "tpr": 1.0}]) == 0.5
    assert compute_roc_auc([{"fpr": 0.0, "tpr": 1.0}, {"fpr": 1.0, "tpr": 1.0}]) == 1.0
    # A single point is not an AUC.
    assert compute_roc_auc([{"fpr": 0.0, "tpr": 1.0}]) is None
    assert compute_roc_auc([]) is None


def test_threshold_sweep_sensitivity_bounds_and_records():
    from eval.threshold_sweep import sweep_thresholds
    mock_evals = [
        {"id": "p1", "label": "malicious", "score": 12.0, "top_finding_score": 12.0, "verdict": "MALICIOUS-EVIDENT", "signal_classes": ["canary_access"]},
        {"id": "p2", "label": "malicious", "score": 3.8, "top_finding_score": 3.8, "verdict": "SUSPICIOUS", "signal_classes": []},
        {"id": "p3", "label": "clean", "score": 0.0, "top_finding_score": 0.0, "verdict": "BENIGN-CONSISTENT", "signal_classes": []},
        {"id": "p4", "label": "clean", "score": 0.0, "top_finding_score": 0.0, "verdict": "BENIGN-CONSISTENT", "signal_classes": []},
    ]
    res = sweep_thresholds(mock_evals)
    assert res["auc_label"] == "decided cases only"
    assert res["auc"] is None or 0.0 <= res["auc"] <= 1.0
    assert res["inconclusive"] == 0
    sens = res["sensitivity"]
    assert sens["nominal_threshold"] == 4.0
    assert sens["minus_20_pct"]["threshold"] == 3.2
    assert sens["plus_20_pct"]["threshold"] == 4.8
    # p2 has score 3.8: flagged at 3.2, but NOT flagged at 4.0 or 4.8
    flips = sens["flipping_packages"]
    flip_ids = [f["id"] for f in flips]
    assert "p2" in flip_ids


def test_compute_rule_coverage_structure():
    from eval.threshold_sweep import compute_rule_coverage
    mock_evals = [
        {"id": "bad1", "label": "malicious", "verdict": "MALICIOUS-EVIDENT", "rules": ["canary_read_then_network", "network_unclaimed"], "score": 16.0},
        {"id": "good1", "label": "clean", "verdict": "BENIGN-CONSISTENT", "rules": [], "score": 0.0},
    ]
    cov = compute_rule_coverage(mock_evals)
    assert "verdict_categories" in cov
    assert "rule_summary" in cov
    assert "package_matrix" in cov
    canary_summary = next((r for r in cov["rule_summary"] if r["rule"] == "canary_read_then_network"), None)
    assert canary_summary is not None
    assert canary_summary["malicious_evident"] == 1
    assert canary_summary["total_hits"] == 1


def test_heatmap_renders_all_three_sections():
    from eval.heatmap import render
    mock_results = {
        "dataset": "labels.yaml",
        "n_malicious": 2,
        "n_clean": 2,
        "tools": {
            "trustlens": {
                "available": True,
                "recall_by_trigger_gate": {"install|none": {"detected": 1, "total": 1, "recall": 1.0}},
                "per_package": {
                    "p1": {"label": "malicious", "verdict": "MALICIOUS-EVIDENT", "score": 10.0, "rules": ["decoded_exec"], "flagged": True},
                    "p2": {"label": "clean", "verdict": "BENIGN-CONSISTENT", "score": 0.0, "rules": [], "flagged": False},
                },
            }
        },
    }
    html = render(mock_results)
    assert "id='recall-matrix'" in html
    assert "id='rule-coverage'" in html
    assert "id='roc-sweep'" in html
    assert "<svg" in html
    assert "AUC n/a (decided cases only)" in html or "ROC AUC =" in html
    assert "T=4.0" in html
    assert "Detection Rule Hits by Verdict Category" in html


def test_nine_abstentions_and_one_tp_do_not_report_auc_one():
    from eval.threshold_sweep import sweep_thresholds
    pkgs = [
        {
            "id": f"abs{i}",
            "label": "malicious",
            "score": 0.0,
            "top_finding_score": 0.0,
            "verdict": "INCONCLUSIVE",
            "signal_classes": [],
            "inconclusive": True,
        }
        for i in range(9)
    ]
    pkgs.append({
        "id": "tp1",
        "label": "malicious",
        "score": 12.0,
        "top_finding_score": 12.0,
        "verdict": "MALICIOUS-EVIDENT",
        "signal_classes": ["canary_access"],
        "inconclusive": False,
    })
    res = sweep_thresholds(pkgs)
    assert res["auc"] is None
    assert res["auc"] != 1.0
    assert res["auc_label"] == "decided cases only"
    assert res["inconclusive"] == 9
    assert res["decided_malicious"] == 1
    assert res["decided_clean"] == 0
    nominal = res["sensitivity"]["nominal"]
    assert nominal["tpr"] == 1.0
    assert nominal["fpr"] is None
    assert nominal["tp"] == 1
    assert nominal["inconclusive"] == 9


def test_mostly_inconclusive_perfect_decided_split_is_not_auc_one():
    """Score-0 clean rows are flagged only at T<=0, which is not imputed as (1, 1)."""
    from eval.threshold_sweep import sweep_thresholds
    pkgs = [
        {"id": "evil", "label": "malicious", "score": 12.0, "top_finding_score": 12.0, "verdict": "MALICIOUS-EVIDENT", "signal_classes": ["canary_access"], "inconclusive": False},
        {"id": "delayed", "label": "malicious", "score": 5.4, "top_finding_score": 5.4, "verdict": "MALICIOUS-EVIDENT", "signal_classes": ["decoded_exec"], "inconclusive": False},
        {"id": "clean_slug", "label": "clean", "score": 0.0, "top_finding_score": 0.0, "verdict": "BENIGN-CONSISTENT", "signal_classes": [], "inconclusive": False},
        {"id": "rest", "label": "clean", "score": 0.0, "top_finding_score": 0.0, "verdict": "BENIGN-CONSISTENT", "signal_classes": [], "inconclusive": False},
    ]
    for i in range(22):
        pkgs.append({
            "id": f"inc{i}",
            "label": "clean" if i % 2 else "malicious",
            "score": 0.0,
            "top_finding_score": 0.0,
            "verdict": "INCONCLUSIVE",
            "signal_classes": [],
            "inconclusive": True,
        })
    res = sweep_thresholds(pkgs)
    assert res["inconclusive"] == 22
    assert res["auc"] is None
    assert res["auc"] != 1.0
    assert res["auc_label"] == "decided cases only"


def test_category_cell_uses_decided_denominator():
    from eval.run_eval import format_category_cell
    assert format_category_cell(1, 1, 2) == "1/1 (inconclusive 2)"
    cell = format_category_cell(0, 4, 2, [0.0, 0.49])
    assert cell.startswith("0/4 ")
    assert "inconclusive 2" in cell
    assert "/6" not in cell
    assert format_category_cell(0, 0, 5) == "- (inconclusive 5)"


def test_get_tool_version_does_not_invent_literals(monkeypatch):
    from eval.run_eval import get_tool_version
    monkeypatch.setattr("eval.run_eval.find_executable", lambda _name: "/fake/tool")

    class _Proc:
        stdout = ""
        stderr = ""

    monkeypatch.setattr("eval.run_eval.subprocess.run", lambda *_a, **_k: _Proc())
    assert get_tool_version("guarddog") == "unknown"
    assert get_tool_version("pipcanary") == "unknown"
    assert "3.2.0" not in get_tool_version("guarddog")
    assert "0.1.1" not in get_tool_version("pipcanary")

    def _boom(*_a, **_k):
        raise OSError("nope")

    monkeypatch.setattr("eval.run_eval.subprocess.run", _boom)
    assert get_tool_version("guarddog") == "unknown"
    assert get_tool_version("pipcanary") == "unknown"


def test_build_noise_whitelist_drops_unmatchable_proc_globs(tmp_path):
    from bench.calibration.build_noise_whitelist import main
    csv_path = tmp_path / "traces.csv"
    benign = "0,python;ld;clear,cc1;pip3,strace;systemd-oomd;ThreadPoolForeg;cc1plus\n"
    malicious = "1,python,cc1,strace\n"
    csv_path.write_text("Level,Read_Processes,Write_Processes,File_Access_Processes\n" + benign * 20 + malicious, encoding="utf-8")
    out = tmp_path / "noise_whitelist.yaml"
    assert main(["--csv", str(csv_path), "--out", str(out), "--min-prevalence", "0.02"]) == 0
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    globs = []
    for rule in data["rules"]:
        if rule.get("source") == "seed":
            assert "benign_prevalence" not in rule
        if rule.get("path_glob"):
            globs.append(rule["path_glob"])
    assert _BANNED_PROC_GLOBS.isdisjoint(globs)
    text = out.read_text(encoding="utf-8")
    assert "127.0.0.1*" not in text
    assert "localhost*" not in text
    assert "TEST_*" not in text
    assert "127.0.0.1" in text


def test_build_noise_whitelist_emits_exact_loopback_host(tmp_path):
    from bench.calibration.build_noise_whitelist import main
    from bench.tools.cross_check_whitelist import cross_check
    csv_path = tmp_path / "dns.csv"
    rows = ["0,127.0.0.1\n"] * 20
    csv_path.write_text("Level,dns\n" + "".join(rows), encoding="utf-8")
    out = tmp_path / "noise_whitelist.yaml"
    assert main(["--csv", str(csv_path), "--cols", "dns", "--out", str(out), "--min-prevalence", "0.02"]) == 0
    text = out.read_text(encoding="utf-8")
    assert "*127.0.0.1*" not in text
    data = yaml.safe_load(text)
    hosts = [r for r in data["rules"] if "127.0.0.1" in str(r.get("host_glob", ""))]
    assert hosts
    assert all(r["host_glob"] == "127.0.0.1" for r in hosts)
    measured = [r for r in hosts if r.get("source") != "seed"]
    assert measured and measured[0]["host_glob"] == "127.0.0.1"
    assert cross_check(out)["is_safe"] is True


def _outside_snapshot(root: Path) -> dict[str, bytes | None]:
    snap: dict[str, bytes | None] = {}
    if not root.exists():
        return snap
    for path in root.rglob("*"):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            snap[rel] = b"SYMLINK"
        elif path.is_file():
            snap[rel] = path.read_bytes()
        else:
            snap[rel] = None
    return snap


def _build_malicious_zip(path: Path, abs_name: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("ok.txt", "ok")
        zf.writestr("../escaped.txt", "pwned")
        zf.writestr("subdir/../../escaped2.txt", "pwned")
        zf.writestr(abs_name, "abs-pwn")
        info = zipfile.ZipInfo("escape_link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"../linked_outside")
        zf.writestr("escape_link/pwned.txt", "via-link")


def _build_malicious_tar(path: Path, abs_name: str) -> None:
    with tarfile.open(path, "w:gz") as tf:
        payload = b"ok"
        info = tarfile.TarInfo("ok.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        bad = b"pwned"
        trav = tarfile.TarInfo("../escaped.txt")
        trav.size = len(bad)
        tf.addfile(trav, io.BytesIO(bad))
        absolute = tarfile.TarInfo(abs_name)
        absolute.size = len(bad)
        tf.addfile(absolute, io.BytesIO(bad))
        link = tarfile.TarInfo("escape_link")
        link.type = tarfile.SYMTYPE
        link.linkname = ".."
        tf.addfile(link)


def _assert_contained(root: Path, dest: Path, before: dict[str, bytes | None]) -> None:
    assert (dest / "ok.txt").read_text(encoding="utf-8") == "ok"
    for path in dest.rglob("*"):
        assert not path.is_symlink()
    after = _outside_snapshot(root)
    for rel, content in after.items():
        if rel == "dest" or rel.startswith("dest/"):
            continue
        assert rel in before, rel
        assert before[rel] == content
    assert not (root / "escaped.txt").exists()
    assert not (root / "escaped2.txt").exists()
    assert not (root / "abs_escaped.txt").exists()


def test_malicious_archive_data_filter_stays_inside_destination(tmp_path):
    """Traversal and symlink members must not write outside the destination."""
    import shutil
    abs_name = str(tmp_path / "abs_escaped.txt")
    script = ROOT / "scripts" / "extract_in_sandbox.sh"
    use_sandbox = shutil.which("bwrap") is not None and script.is_file()
    for builder, name in ((_build_malicious_zip, "evil.zip"), (_build_malicious_tar, "evil.tar.gz")):
        case = tmp_path / name.replace(".", "_")
        case.mkdir()
        archive = case / name
        builder(archive, abs_name)
        dest = case / "dest"
        marker = case / "outside.txt"
        marker.write_bytes(b"untouched")
        before = _outside_snapshot(case)
        if use_sandbox:
            proc = subprocess.run(["bash", str(script), str(archive), str(dest)], capture_output=True, text=True, check=False)
            assert proc.returncode == 0, proc.stderr
        else:
            from bench.tools.archive_filter import extract_archive_filtered
            assert extract_archive_filtered(archive, dest) is True
        assert marker.read_bytes() == b"untouched"
        _assert_contained(case, dest, before)
        assert not Path(abs_name).exists()
        assert not (dest / "escaped.txt").exists()
        assert not (dest / "escaped2.txt").exists()
        link = dest / "escape_link"
        assert not link.is_symlink()
        if name.endswith(".tar.gz"):
            assert not link.exists()
        elif link.exists():
            assert link.is_dir()


def test_safe_extract_archive_does_not_fall_back_on_host(monkeypatch, tmp_path):
    from bench.tools import sample_malregistry as mr
    archive = tmp_path / "plain.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ok.txt", "ok")
        zf.writestr("../escaped.txt", "pwned")
    dest = tmp_path / "out"
    monkeypatch.setattr(mr.shutil, "which", lambda *_a, **_k: None)
    assert mr.safe_extract_archive(archive, dest) is False
    assert not (dest / "ok.txt").exists()
    assert not (tmp_path / "escaped.txt").exists()

    class _Failed:
        returncode = 1
        stdout = ""
        stderr = "sandbox failed"

    monkeypatch.setattr(mr.shutil, "which", lambda name, *_a, **_k: "/usr/bin/bwrap" if name == "bwrap" else None)
    monkeypatch.setattr(mr.subprocess, "run", lambda *_a, **_k: _Failed())
    assert mr.safe_extract_archive(archive, dest) is False
    assert not dest.exists()
    assert not (dest / "ok.txt").exists()


def test_roc_chart_omits_zero_threshold_and_does_not_shade_zero_width():
    import re

    from eval.heatmap import _generate_roc_svg
    records = [
        {"threshold": 0.0, "tpr": 1.0, "fpr": 1.0},
        {"threshold": 4.0, "tpr": 1.0, "fpr": 0.0},
        {"threshold": 8.0, "tpr": 1.0, "fpr": 0.0},
    ]
    svg = _generate_roc_svg(records, None, 4.0, decided_malicious=2, decided_clean=2)
    assert "AUC n/a (decided cases only)" in svg
    assert "<path " not in svg
    assert "fill-opacity" not in svg
    assert "FPR=1" not in svg

    wide = [
        {"threshold": 0.0, "tpr": 1.0, "fpr": 1.0},
        {"threshold": 2.0, "tpr": 1.0, "fpr": 0.0},
        {"threshold": 6.0, "tpr": 0.5, "fpr": 0.25},
    ]
    drawn = _generate_roc_svg(wide, 0.875, 4.0, decided_malicious=2, decided_clean=2)
    path = re.search(r'<path d="([^"]+)"', drawn)
    assert path is not None
    xs = [float(v) for v in re.findall(r"[ML] ([\d.]+)", path.group(1))]
    assert xs
    assert max(xs) < 400


def test_heatmap_abstained_trigger_is_not_labelled_not_run():
    from eval.heatmap import render
    html = render({
        "dataset": "labels.yaml",
        "n_malicious": 6,
        "n_clean": 0,
        "tools": {
            "trustlens": {
                "available": True,
                "recall_by_trigger_gate": {
                    "call|none": {"detected": 1, "decided": 1, "inconclusive": 5, "total": 6, "recall": 1.0},
                },
                "per_package": {},
            },
            "pipcanary": {"available": False, "recall_by_trigger_gate": {}},
        },
        "threshold_sweep": {
            "auc": None,
            "nominal_threshold": 4.0,
            "sweep": [],
            "sensitivity": {},
            "inconclusive": 5,
            "decided_malicious": 1,
            "decided_clean": 0,
        },
        "rule_coverage": {"rule_summary": [], "package_matrix": []},
    })
    assert "1/1 (inconclusive 5)" in html
    assert "(100%)" not in html
    assert html.count(">not run</td>") == 1


def test_trigger_recall_uses_decided_rows_plus_inconclusive():
    rows = [
        {"label": "malicious", "flagged": True, "trigger": "call", "gate": "none", "runtime_s": 0.01},
        {"label": "malicious", "flagged": None, "trigger": "call", "gate": "none", "runtime_s": 0.01},
        {"label": "malicious", "flagged": None, "trigger": "call", "gate": "none", "runtime_s": 0.01},
    ]
    cell = confusion(rows)["recall_by_trigger_gate"]["call|none"]
    assert cell["detected"] == 1
    assert cell["decided"] == 1
    assert cell["inconclusive"] == 2
    assert cell["total"] == 3
    assert cell["recall"] == 1.0


def test_triage_marks_inconclusive_malicious_as_abstain():
    from eval.run_eval import generate_triage_report
    pk = [
        {"id": "toy", "label": "malicious", "category": "planted"},
        {"id": "missed", "label": "malicious", "category": "planted"},
    ]
    per = {"trustlens": {
        "toy": {"verdict": "INCONCLUSIVE", "flagged": None},
        "missed": {"verdict": "BENIGN-CONSISTENT", "flagged": False},
    }}
    text = "\n".join(generate_triage_report(pk, per))
    toy_line = next(line for line in text.splitlines() if line.startswith("| toy |"))
    miss_line = next(line for line in text.splitlines() if line.startswith("| missed |"))
    assert "ABSTAIN" in toy_line
    assert "MISS" not in toy_line
    assert "MISS" in miss_line


def test_block_policy_suspicious_is_not_flagged_inconclusive_abstains():
    from eval.run_eval import tl_flagged
    assert tl_flagged({"verdict": "INCONCLUSIVE"}, "block") is None
    assert tl_flagged({"verdict": "INCONCLUSIVE"}, "review") is None
    assert tl_flagged({"verdict": "SUSPICIOUS"}, "block") is False
    assert tl_flagged({"verdict": "SUSPICIOUS"}, "review") is True
    assert tl_flagged({"verdict": "MALICIOUS-EVIDENT"}, "block") is True
    assert tl_flagged({"verdict": "BENIGN-CONSISTENT"}, "block") is False
    rows = [
        {"label": "malicious", "flagged": tl_flagged({"verdict": "SUSPICIOUS"}, "block"), "trigger": "call", "gate": "none", "runtime_s": 0.1},
        {"label": "malicious", "flagged": tl_flagged({"verdict": "INCONCLUSIVE"}, "block"), "trigger": "call", "gate": "none", "runtime_s": 0.1},
        {"label": "clean", "flagged": tl_flagged({"verdict": "SUSPICIOUS"}, "block"), "trigger": None, "gate": None, "runtime_s": 0.1},
        {"label": "clean", "flagged": tl_flagged({"verdict": "BENIGN-CONSISTENT"}, "block"), "trigger": None, "gate": None, "runtime_s": 0.1},
    ]
    got = confusion(rows)
    assert (got["tp"], got["fn"], got["fp"], got["tn"], got["inconclusive"]) == (0, 1, 0, 2, 1)


def test_whitelist_rejects_globs_that_match_adversarial_strings(tmp_path):
    import fnmatch

    from bench.tools.cross_check_whitelist import ADVERSARIAL_PROBES, cross_check
    live = cross_check(ROOT / "bench/calibration/noise_whitelist.yaml")
    assert live["is_safe"] is True
    data = yaml.safe_load((ROOT / "bench/calibration/noise_whitelist.yaml").read_text(encoding="utf-8"))
    for rule in data["rules"]:
        glob = str(rule.get("host_glob") or rule.get("env_glob") or "")
        for probe in ADVERSARIAL_PROBES:
            assert fnmatch.fnmatch(probe, glob) is False
    wide = tmp_path / "wide.yaml"
    wide.write_text(
        "rules:\n"
        "- {capability: network, host_glob: '127.0.0.1*', reason: wide, source: seed}\n"
        "- {capability: network, host_glob: 'localhost*', reason: wide, source: seed}\n"
        "- {capability: env_secrets, env_glob: 'TEST_*', reason: wide, source: seed}\n",
        encoding="utf-8",
    )
    bad = cross_check(wide)
    assert bad["is_safe"] is False
    matched = {v["matched_string"] for v in bad["violations"]}
    for probe in ADVERSARIAL_PROBES:
        assert probe in matched


def test_find_pkg_root_does_not_seed_readme_in_empty_dir(tmp_path):
    from bench.tools import sample_malregistry as mr
    empty = tmp_path / "empty"
    empty.mkdir()
    assert mr.find_pkg_root(empty, "evilpkg") is None
    assert not (empty / "README.md").exists()


def test_malregistry_does_not_label_when_extract_fails(tmp_path, monkeypatch):
    from bench.tools import sample_malregistry as mr
    mr_dir = tmp_path / "mr"
    pkg = mr_dir / "evilpkg" / "1.0"
    pkg.mkdir(parents=True)
    (pkg / "evilpkg-1.0.tar.gz").write_bytes(b"not-an-archive")
    monkeypatch.setattr(mr, "MR_DIR", mr_dir)
    monkeypatch.setattr(mr, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(mr, "ensure_mr_clone", lambda: None)
    monkeypatch.setattr(mr.subprocess, "run", lambda *_a, **_k: subprocess.CompletedProcess(args=[], returncode=0))
    monkeypatch.setattr(mr, "safe_extract_archive", lambda *_a, **_k: False)
    out = tmp_path / "labels.yaml"
    assert mr.main(["--packages", "evilpkg", "--out-labels", str(out)]) == 0
    assert not out.exists()
    assert not (tmp_path / "extracted").exists()
    assert not list(mr_dir.rglob("README.md"))


def test_extract_script_does_not_create_dest_on_failure(tmp_path):
    script = ROOT / "scripts" / "extract_in_sandbox.sh"
    dest = tmp_path / "nested" / "out"
    missing = tmp_path / "missing.zip"
    proc = subprocess.run(["bash", str(script), str(missing), str(dest)], capture_output=True, text=True, check=False)
    assert proc.returncode != 0
    assert not dest.exists()
    assert not dest.parent.exists() or not any(dest.parent.iterdir())


def test_datadog_extract_failure_does_not_create_dest_or_keep_html_claim(tmp_path, monkeypatch):
    from bench.tools.sample_datadog import descriptive_claim_line, get_readme_summary, safe_extract_zip
    dest = tmp_path / "pkg"
    monkeypatch.setattr("bench.tools.sample_datadog.shutil.which", lambda *_a, **_k: None)
    assert safe_extract_zip(tmp_path / "a.zip", dest) is False
    assert not dest.exists()
    root = tmp_path / "readme"
    root.mkdir()
    (root / "README.md").write_text(
        "![badge](https://img.shields.io/badge/x)\n\n<p align=\"center\">\n\nActual package purpose\n",
        encoding="utf-8",
    )
    assert get_readme_summary(root) == "Actual package purpose"
    (root / "README.md").write_text("<p align=\"center\">\n<img src=\"x\">\n", encoding="utf-8")
    assert get_readme_summary(root) is None
    assert descriptive_claim_line('<p align="center">') is None
    assert descriptive_claim_line("uninspected Datadog sample") is None
    labels = yaml.safe_load((ROOT / "bench/labels_datadog.yaml").read_text(encoding="utf-8"))
    for pkg in labels["packages"]:
        claim = str(pkg["claim"])
        assert claim != "uninspected Datadog sample"
        assert claim.lstrip().startswith("<") is False
        assert "<p align" not in claim
        if claim == "not stated":
            assert "no descriptive README line available" in pkg.get("notes", "")


def test_held_out_wording_is_a_reported_slice():
    text = (ROOT / "bench/held_out.yaml").read_text(encoding="utf-8")
    assert "held-out from rule/heuristic tuning" not in text
    assert "not a withheld tuning set" in text
    docs = (ROOT / "docs/DATASETS.md").read_text(encoding="utf-8")
    assert "20,269" not in docs
    assert "6,683 PyPI + 13,565 npm" in docs
    assert "20,248" in docs





