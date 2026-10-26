"""Dev C. Labels, metrics, dataset tooling (offline parts only)."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

from eval.metrics import confusion, wilson
from trustlens.contracts import ROOT


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
    r = subprocess.run([sys.executable, "-m", "eval.run_eval", "--runner", "fixture", "--tools", "trustlens", "--out", str(tmp_path)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert (Path(tmp_path) / "results.json").exists()
