"""Dev B. Fixtures -> fingerprint -> verdict. Add one test per rule + one per FP you fix."""
import json

import pytest

from trustlens.claims import extract_claims
from trustlens.contracts import EXAMPLES, ROOT, validate
from trustlens.engine import evaluate
from trustlens.fingerprint import build_fingerprint

BENCH = ROOT / "bench" / "packages"
CASES = {
    "malicious/evil_slug": "MALICIOUS-EVIDENT",
    "malicious/delayed_slug": "MALICIOUS-EVIDENT",
    "clean/clean_slug": "BENIGN-CONSISTENT",
    "clean/rest_wrapper": "BENIGN-CONSISTENT",
}


def run(rel):
    d = EXAMPLES / rel.split("/")[1]
    meta = json.loads((d / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / rel))
    fp = build_fingerprint(str(d / "raw_events.jsonl"), meta, claims["package"])
    v = evaluate(fp, claims)
    for k, o in (("claims", claims), ("fingerprint", fp), ("verdict", v)):
        validate(k, o)
    return fp, claims, v


@pytest.mark.parametrize("rel,expected", CASES.items())
def test_expected_verdicts(rel, expected):
    assert run(rel)[2]["verdict"] == expected


def test_evil_slug_has_canary_in_bytes_and_evidence_chain():
    v = run("malicious/evil_slug")[2]
    rules = {f["rule"] for f in v["findings"]}
    assert {"canary_in_outgoing_bytes", "network_unclaimed"} <= rules
    assert all(f["events"] and f["explanation"] for f in v["findings"])


def test_delayed_slug_needs_ci_profile_to_show():
    fp, _, v = run("malicious/delayed_slug")
    assert any(f["rule"] == "env_differential" for f in v["findings"])


def test_rest_wrapper_network_is_claim_licensed_not_a_finding():
    v = run("clean/rest_wrapper")[2]
    assert not [f for f in v["findings"] if f["rule"] == "network_unclaimed"]


def test_synthetic_pth_startup_is_flagged():
    d = EXAMPLES / "_synthetic_pth_startup"
    claims = {"schema_version": "1.0", "package": {"name": "zz-helper", "version": "1", "ecosystem": "pypi"},
              "intents": [{"intent": "string_util", "confidence": 0.6, "quote": "string helper", "source": "readme"}],
              "claims": [], "unknown_intent": False, "declared_entry_points": []}
    fp = build_fingerprint(str(d / "raw_events.jsonl"), json.loads((d / "run_meta.json").read_text()), claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "MALICIOUS-EVIDENT"
    signals = set(v["independent_signals"])
    assert {"startup_hook", "canary_access", "network_unclaimed"} <= signals
    pth_findings = [f for f in v["findings"] if f["rule"] == "startup_hook"]
    assert pth_findings
    assert "zz_helper.pth:1" in pth_findings[0]["explanation"] or "site-packages/zz_helper.pth:1" in pth_findings[0]["explanation"]


def test_plain_path_pth_is_info_not_strong(tmp_path):
    raw = tmp_path / "raw.jsonl"
    raw.write_text(json.dumps({
        "seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
        "kind": "startup.pth", "detail": {"file": "site-packages/plain.pth", "line_text": "/opt/custom/path"},
        "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "fs_diff", "file": "plain.pth", "line": 1}
    }) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    # Plain path should not be classified as strong startup_hook
    assert "startup_hook" not in v["independent_signals"]
    assert v["verdict"] != "MALICIOUS-EVIDENT"


def test_persistence_detection(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.bashrc"}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 1, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.config/autostart/bad.desktop"}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 2, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.config/systemd/user/bad.service"}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 3, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.ssh/authorized_keys"}, "outcome": "succeeded", "attributed_to": "pkg"},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert any(f["rule"] == "persistence" and f["signal_class"] == "persistence" for f in v["findings"])
    assert "persistence" in v["independent_signals"]


def test_download_exec_detection(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/tmp/stage2.sh"}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 1, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "proc.spawn", "detail": {"argv": ["/bin/bash", "/tmp/stage2.sh"]}, "outcome": "succeeded", "attributed_to": "pkg"},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert any(f["rule"] == "download_exec" and f["signal_class"] == "dropper" for f in v["findings"])
    assert "dropper" in v["independent_signals"]


def test_no_run_means_inconclusive_never_benign(tmp_path):
    (tmp_path / "raw.jsonl").write_text("")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"]["install_completed"] = False
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    v = evaluate(build_fingerprint(str(tmp_path / "raw.jsonl"), meta, claims["package"]), claims)
    assert v["verdict"] == "INCONCLUSIVE"


def test_claim_extraction_http_client():
    c = extract_claims(str(BENCH / "clean/rest_wrapper"))
    assert any(i["intent"] == "http_client" for i in c["intents"])


def test_claim_extractor_table_driven_samples(tmp_path):
    # Sample 1: rest_wrapper (golden)
    c1 = extract_claims(str(BENCH / "clean/rest_wrapper"))
    assert any(cl["capability"] == "network" for cl in c1["claims"])
    assert any(cl["capability"] == "env_secrets" for cl in c1["claims"])
    assert not c1["unknown_intent"]

    # Sample 2: clean_slug (golden string_util)
    c2 = extract_claims(str(BENCH / "clean/clean_slug"))
    assert any(i["intent"] == "string_util" for i in c2["intents"])
    assert c2["claims"] == []

    # Sample 3: Empty README
    p3 = tmp_path / "pkg3"
    p3.mkdir()
    (p3 / "README.md").write_text("")
    (p3 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg3', version='1.0')\n")
    c3 = extract_claims(str(p3))
    assert c3["unknown_intent"] is True
    assert c3["claims"] == []

    # Sample 4: Short README (< 20 chars)
    p4 = tmp_path / "pkg4"
    p4.mkdir()
    (p4 / "README.md").write_text("Hello world")
    (p4 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg4', version='1.0')\n")
    c4 = extract_claims(str(p4))
    assert c4["unknown_intent"] is True
    assert c4["claims"] == []

    # Sample 5: README "string utility" with 'requests' dependency -> network NOT licensed
    p5 = tmp_path / "pkg5"
    p5.mkdir()
    (p5 / "README.md").write_text("A simple string formatting utility and slugifier.")
    (p5 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg5', version='1.0', install_requires=['requests'])\n")
    c5 = extract_claims(str(p5))
    assert any(i["intent"] == "string_util" for i in c5["intents"])
    assert not any(cl["capability"] == "network" for cl in c5["claims"])

    # Sample 6: Package with console_scripts -> cli_tool with entry_points source
    p6 = tmp_path / "pkg6"
    p6.mkdir()
    (p6 / "README.md").write_text("Tool to manage files and run tasks from your terminal.")
    (p6 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg6', version='1.0', entry_points={'console_scripts': ['my-cli = pkg6.cli:main']})\n")
    c6 = extract_claims(str(p6))
    assert "my-cli = pkg6.cli:main" in c6["declared_entry_points"]
    assert any(i["intent"] == "cli_tool" and i["source"] == "entry_points" for i in c6["intents"])
    assert any(cl["capability"] == "subprocess" for cl in c6["claims"])

    # Sample 7: Package with classifier -> http_client
    p7 = tmp_path / "pkg7"
    p7.mkdir()
    (p7 / "README.md").write_text("Custom service connector library.")
    (p7 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg7', version='1.0', classifiers=['Topic :: Internet :: WWW/HTTP'])\n")
    c7 = extract_claims(str(p7))
    assert any(i["intent"] == "http_client" and i["source"] == "classifier" for i in c7["intents"])
    assert any(cl["capability"] == "network" for cl in c7["claims"])

    # Sample 8: Code fences containing 'requests' stripped; does not license network for pure text util
    p8 = tmp_path / "pkg8"
    p8.mkdir()
    (p8 / "README.md").write_text("A fast text parser and string tokenizer.\n```python\nimport requests\nresp = requests.get('https://example.com')\n```\n")
    (p8 / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg8', version='1.0')\n")
    c8 = extract_claims(str(p8))
    assert any(i["intent"] == "string_util" for i in c8["intents"])
    assert not any(i["intent"] == "http_client" for i in c8["intents"])
    assert c8["claims"] == []


def test_canary_matched_event_survives_any_whitelist(tmp_path):
    raw = tmp_path / "raw.jsonl"
    event = {
        "seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
        "kind": "file.read", "detail": {"path": "/w/home/.ssh/id_rsa"},
        "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "pkg",
        "evidence": {"layer": "audit", "file": "setup.py", "line": 10}
    }
    raw.write_text(json.dumps(event) + "\n")
    aggressive_whitelist = [
        {"capability": "fs_read_sensitive", "path_glob": "~/.ssh/*", "reason": "test suppress", "source": "test"}
    ]
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"], whitelist=aggressive_whitelist)
    assert len(fp["events"]) == 1
    assert fp["events"][0]["canary_hit"] is True
    assert fp["events"][0]["canary_ids"] == ["ssh_key"]
    assert fp["coverage"]["whitelisted_or_dropped_events"] == 0


def test_toolchain_events_dropped(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "proc.spawn", "detail": {"argv": ["pip", "wheel"]}, "outcome": "succeeded", "attributed_to": "toolchain"},
        {"seq": 1, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "proc.spawn", "detail": {"argv": ["echo", "pkg"]}, "outcome": "succeeded", "attributed_to": "pkg"}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert len(fp["events"]) == 1
    assert fp["events"][0]["attributed_to"] == "pkg"
    assert fp["coverage"]["whitelisted_or_dropped_events"] >= 1


def test_event_level_deduplication_aggregates_with_count(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": i, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "file.read", "detail": {"path": "/etc/shadow"}, "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 20}}
        for i in range(50)
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert len(fp["events"]) == 1
    assert fp["events"][0]["detail"]["count"] == 50
    assert fp["events"][0]["count"] == 50
    assert fp["coverage"]["whitelisted_or_dropped_events"] == 49


def test_dep_attribution_discount(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "proc.spawn", "detail": {"argv": ["git", "status"]}, "outcome": "succeeded",
         "attributed_to": "dep:dulwich", "evidence": {"layer": "audit", "file": "dulwich/repo.py", "line": 15}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "proc.spawn", "detail": {"argv": ["git", "status"]}, "outcome": "succeeded",
         "attributed_to": "dep:dulwich", "evidence": {"layer": "audit", "file": "dulwich/repo.py", "line": 15}}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    f = [finding for finding in v["findings"] if finding["rule"] == "capability_not_claimed"][0]
    assert "[Attributed to dependency: dep:dulwich]" in f["explanation"]
    assert f["score"] == 1.26


@pytest.mark.parametrize("mutation_key,mutation_val", [
    ("install_completed", False),
    ("profiles_run", ["dev"]),
    ("phases_run", []),
    ("callables_exercised", 0),  # callables_total is 1 in clean_slug -> 0/1 < 0.5
])
def test_coverage_mutations_lead_to_inconclusive(tmp_path, mutation_key, mutation_val):
    raw = tmp_path / "raw.jsonl"
    raw.write_text("")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"][mutation_key] = mutation_val
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "INCONCLUSIVE"
    assert v["action"] == "REVIEW"
    assert v["confidence"] == "low"


def test_timeout_error_dominates_leads_to_inconclusive(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "run.error", "detail": {"where": "install", "message": "Command timed out after 120s"},
         "outcome": "blocked", "attributed_to": "toolchain"}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"]["install_note"] = "timeout"
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "INCONCLUSIVE"
    assert v["confidence"] == "low"


def test_single_strong_signal_is_suspicious_not_block(tmp_path):
    raw = tmp_path / "raw.jsonl"
    # Single strong class: persistence symmetrically in dev and ci without canary
    events = [
        {"seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.bashrc"}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 1, "phase": "install", "trigger": "install", "profile": "ci", "variant": "default",
         "kind": "file.write", "detail": {"path": "/w/home/.bashrc"}, "outcome": "succeeded", "attributed_to": "pkg"}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "SUSPICIOUS"
    assert v["action"] == "REVIEW"
    assert v["independent_signals"] == ["persistence"]


def test_high_confidence_benign_coverage():
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"]["phases_run"] = ["install", "startup", "import", "call", "cli"]
    meta["coverage"]["triggers_run"] = ["install", "fresh_startup", "import_all", "call_all", "cli"]
    meta["coverage"]["variants_run"] = ["default", "clock+30d"]
    meta["coverage"]["strace_layer"] = True
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(EXAMPLES / "clean_slug" / "raw_events.jsonl"), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "BENIGN-CONSISTENT"
    assert v["confidence"] == "high"
