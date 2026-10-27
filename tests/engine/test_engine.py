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
    fp, _, v = run("malicious/evil_slug")
    rules = {f["rule"] for f in v["findings"]}
    assert {"canary_in_outgoing_bytes", "network_unclaimed"} <= rules
    ev_map = {e["id"]: e["seq"] for e in fp["events"]}
    for f in v["findings"]:
        assert f["events"] and f["explanation"]
        assert f["evidence"]
        # Verify events are ordered by time (seq)
        seqs = [ev_map[eid] for eid in f["events"] if eid in ev_map]
        assert seqs == sorted(seqs)
        # Verify evidence contains layer/file/line
        for ev in f["evidence"]:
            assert "file" in ev and "line" in ev and "phase" in ev and "profile" in ev and "outcome" in ev
        # Verify sentence explanation structure
        exp = f["explanation"]
        assert f"during {f['phases'][0]}" in exp.lower()
        assert "says «" in exp or "claim" in exp
        assert "Outcome:" in exp


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
    # Plain path should not be classified as strong startup_hook and must forbid SUSPICIOUS
    assert "startup_hook" not in v["independent_signals"]
    assert v["verdict"] != "MALICIOUS-EVIDENT"
    assert v["verdict"] != "SUSPICIOUS"
    assert v["verdict"] == "BENIGN-CONSISTENT"


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


def test_env_differential_gating_detected(tmp_path):
    raw = tmp_path / "raw.jsonl"
    # Action present only in 'ci' profile, absent in 'dev' profile
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "net.connect", "detail": {"dest": "203.0.113.5:80"}, "outcome": "blocked", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 42}}
    ]
    raw.write_text(json.dumps(events[0]) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert any(f["rule"] == "env_differential" and f["signal_class"] == "env_differential" for f in v["findings"])
    assert "env_differential" in v["independent_signals"]


def test_decoded_exec_with_obfuscation(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "import base64; import socket; s = socket.socket()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "lib.py", "line": 8}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "import base64; import socket; s = socket.socket()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "lib.py", "line": 8}}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    f = [finding for finding in v["findings"] if finding["rule"] == "decoded_exec"][0]
    assert f["signal_class"] == "decoded_exec"
    assert "contains obfuscation decoding patterns" in f["explanation"]
    assert "touches network/process APIs" in f["explanation"]


def test_benign_dynamic_exec_shim_not_strong(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "import", "trigger": "import_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"layer": "audit", "file": "jinja2/compiler.py", "line": 50}},
        {"seq": 1, "phase": "import", "trigger": "import_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"layer": "audit", "file": "jinja2/compiler.py", "line": 50}}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    # Benign shim should have signal_class info, not strong decoded_exec and must forbid SUSPICIOUS
    assert "decoded_exec" not in v["independent_signals"]
    assert v["verdict"] != "MALICIOUS-EVIDENT"
    assert v["verdict"] != "SUSPICIOUS"
    assert v["verdict"] == "BENIGN-CONSISTENT"


def test_static_signals_ingested_as_weak_evidence(tmp_path):
    raw = tmp_path / "raw.jsonl"
    raw.write_text("")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    static_sigs = [
        {"source": "guarddog", "rule": "shady-links", "message": "Hidden URL detected", "file": "setup.py", "line": 3}
    ]
    fp = build_fingerprint(str(raw), meta, claims["package"], static_signals=static_sigs)
    v = evaluate(fp, claims)
    # Static signals must be noted in summary and never generate findings with empty events
    assert "Static signals noted: shady-links" in v["summary"]
    assert not any(f["events"] == [] for f in v["findings"])
    assert "static_signal" not in v["independent_signals"]
    assert v["verdict"] != "MALICIOUS-EVIDENT"
    assert v["score"] == 0.5


def test_dependency_attribution_report(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.connect", "detail": {"dest": "93.184.216.34:443"}, "outcome": "blocked",
         "attributed_to": "dep:requests", "evidence": {"layer": "audit", "file": "requests/adapters.py", "line": 400}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "env.read", "detail": {"name": "AWS_ACCESS_KEY_ID"}, "outcome": "succeeded",
         "attributed_to": "dep:urllib3", "evidence": {"layer": "audit", "file": "urllib3/util/ssl_.py", "line": 150}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    validate("verdict", v)

    dep_attr = v["dependency_attribution"]
    assert "requests" in dep_attr
    assert dep_attr["requests"]["name"] == "requests"
    assert dep_attr["requests"]["event_count"] >= 1
    assert "network" in dep_attr["requests"]["capabilities"]
    assert "call" in dep_attr["requests"]["phases"]
    assert dep_attr["requests"]["canary_hit"] is False

    assert "urllib3" in dep_attr
    assert dep_attr["urllib3"]["name"] == "urllib3"
    assert dep_attr["urllib3"]["event_count"] >= 1
    assert "call" in dep_attr["urllib3"]["phases"]


def test_claims_multilingual_readme_fallback(tmp_path):
    # Case 1: Chinese README with no metadata
    p_zh = tmp_path / "pkg_zh"
    p_zh.mkdir()
    (p_zh / "README.md").write_text("这是一个用于高效处理字符串与文本清洗的工具包。提供全面的分词和过滤能力。")
    (p_zh / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_zh', version='1.0')\n")
    c_zh = extract_claims(str(p_zh))
    validate("claims", c_zh)
    assert c_zh["unknown_intent"] is True
    assert c_zh["claims"] == []

    # Case 2: Russian README with no metadata
    p_ru = tmp_path / "pkg_ru"
    p_ru.mkdir()
    (p_ru / "README.md").write_text("Библиотека для форматирования текста и структурирования строк данных.")
    (p_ru / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_ru', version='1.0')\n")
    c_ru = extract_claims(str(p_ru))
    validate("claims", c_ru)
    assert c_ru["unknown_intent"] is True
    assert c_ru["claims"] == []

    # Case 3: Adversarial multi-language README with buried English keywords
    p_adv = tmp_path / "pkg_adv"
    p_adv.mkdir()
    (p_adv / "README.md").write_text("这是一个功能强大的工具，包含 requests 网络调用和 socket 客户端支持。")
    (p_adv / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_adv', version='1.0')\n")
    c_adv = extract_claims(str(p_adv))
    validate("claims", c_adv)
    # Conservative fallback: non-English README must not license network capabilities via buried keywords
    assert c_adv["unknown_intent"] is True
    assert c_adv["claims"] == []

    # Case 4 (Item 10): Chinese README + classifier retains metadata claims
    p_cls = tmp_path / "pkg_cls"
    p_cls.mkdir()
    (p_cls / "README.md").write_text("这是一个用于高效处理网络通讯与数据传输的客户端库。")
    (p_cls / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_cls', version='1.0', classifiers=['Topic :: Internet :: WWW/HTTP'])\n")
    c_cls = extract_claims(str(p_cls))
    validate("claims", c_cls)
    assert c_cls["unknown_intent"] is False
    assert any(cl["capability"] == "network" for cl in c_cls["claims"])


def test_engine_determinism():
    for rel in CASES:
        d = EXAMPLES / rel.split("/")[1]
        meta = json.loads((d / "run_meta.json").read_text())
        claims = extract_claims(str(BENCH / rel))
        fp = build_fingerprint(str(d / "raw_events.jsonl"), meta, claims["package"])

        v_base = evaluate(fp, claims)
        base_dump = json.dumps(v_base, sort_keys=True, indent=2)

        for _ in range(5):
            v_repeat = evaluate(fp, claims)
            repeat_dump = json.dumps(v_repeat, sort_keys=True, indent=2)
            assert base_dump == repeat_dump, f"Engine output non-deterministic for {rel}"


def test_fuzz_event_streams_schema_validity(tmp_path):
    import random
    rng = random.Random(1337)
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))

    kinds = ["file.read", "file.write", "net.connect", "net.send", "proc.spawn", "dyn.exec", "env.read", "run.error", "unknown.custom"]
    phases = ["install", "startup", "import", "call", "cli"]
    profiles = ["dev", "ci"]
    variants = ["default", "clock+30d"]
    outcomes = ["succeeded", "attempted", "blocked", "unknown"]
    attributions = ["pkg", "toolchain", "dep:fuzzlib"]

    for iteration in range(25):
        num_events = rng.randint(1, 15)
        raw_events = []
        for seq in range(num_events):
            kind = rng.choice(kinds)
            detail = {}
            if "file" in kind:
                detail["path"] = f"/tmp/fuzz_{rng.randint(0, 100)}.dat"
            elif "net" in kind:
                detail["dest"] = f"198.51.100.{rng.randint(1, 250)}:8080"
                if rng.random() < 0.2:
                    detail["canary_in_bytes"] = True
            elif "dyn" in kind:
                detail["decoded_snippet"] = "print('fuzz')" if rng.random() < 0.5 else "import base64; b64decode()"
            elif "proc" in kind:
                detail["argv"] = ["/bin/echo", "hello"]

            event = {
                "seq": seq,
                "phase": rng.choice(phases),
                "trigger": "fuzz_trigger",
                "profile": rng.choice(profiles),
                "variant": rng.choice(variants),
                "kind": kind,
                "detail": detail,
                "outcome": rng.choice(outcomes),
                "attributed_to": rng.choice(attributions),
                "evidence": {"layer": "audit", "file": "fuzz.py", "line": seq + 1}
            }
            if rng.random() < 0.2:
                event["canary_match"] = ["ssh_key"]
            raw_events.append(event)

        raw_file = tmp_path / f"fuzz_{iteration}.jsonl"
        raw_file.write_text("\n".join(json.dumps(e) for e in raw_events) + "\n")

        fp = build_fingerprint(str(raw_file), meta, claims["package"])
        validate("fingerprint", fp)

        v = evaluate(fp, claims)
        validate("verdict", v)
        assert v["verdict"] in ("BENIGN-CONSISTENT", "SUSPICIOUS", "MALICIOUS-EVIDENT", "INCONCLUSIVE")
        assert v["action"] in ("PASS", "REVIEW", "BLOCK")
        assert isinstance(v["score"], int | float)


def test_r4_dep_shim_followed_by_socket_fails(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"layer": "audit", "file": "jinja2/compiler.py", "line": 50}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "import socket; s = socket.socket()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 20}},
        {"seq": 2, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "import socket; s = socket.socket()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 20}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    # The dep shim should not prevent the subsequent socket dynamic_exec from being flagged
    assert "decoded_exec" in v["independent_signals"]
    assert v["verdict"] in ("SUSPICIOUS", "MALICIOUS-EVIDENT")
    assert v["action"] in ("REVIEW", "BLOCK")


def test_canary_read_on_dev_and_ci_is_at_least_suspicious(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "file.read", "detail": {"path": "/w/home/.ssh/id_rsa"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "file.read", "detail": {"path": "/w/home/.ssh/id_rsa"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] in ("SUSPICIOUS", "MALICIOUS-EVIDENT")
    assert v["action"] in ("REVIEW", "BLOCK")
    f_canary = [f for f in v["findings"] if f["canary_hit"]]
    assert f_canary
    assert f_canary[0]["score"] >= 4.0

    # Repeat with env secret AWS_SECRET_ACCESS_KEY
    raw_env = tmp_path / "raw_env.jsonl"
    events_env = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "env.read", "detail": {"name": "AWS_SECRET_ACCESS_KEY"},
         "canary_match": ["aws_secret_env"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "env.read", "detail": {"name": "AWS_SECRET_ACCESS_KEY"},
         "canary_match": ["aws_secret_env"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
    ]
    raw_env.write_text("\n".join(json.dumps(e) for e in events_env) + "\n")
    fp_env = build_fingerprint(str(raw_env), meta, claims["package"])
    v_env = evaluate(fp_env, claims)
    assert v_env["verdict"] in ("SUSPICIOUS", "MALICIOUS-EVIDENT")


def test_claimed_ssh_tool_read_stays_quiet(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "file.read", "detail": {"path": "/w/home/.ssh/id_rsa"},
         "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "file.read", "detail": {"path": "/w/home/.ssh/id_rsa"},
         "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = {
        "schema_version": "1.0",
        "package": {"name": "ssh-helper", "version": "1.0", "ecosystem": "pypi"},
        "intents": [{"intent": "ssh_tool", "confidence": 0.8, "quote": "ssh client", "source": "readme"}],
        "claims": [{"capability": "fs_read_sensitive", "basis": "intent_prior", "quote": "ssh client", "source": "readme", "phases_allowed": ["call", "cli"]}],
        "unknown_intent": False,
        "declared_entry_points": []
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    # Claimed read stays quiet
    assert not [f for f in v["findings"] if f["capability"] == "fs_read_sensitive"]
    assert v["verdict"] == "BENIGN-CONSISTENT"


def test_gcloud_and_docker_config_are_fs_read_sensitive():
    from trustlens.fingerprint.normalize import classify
    e_gcloud = {"kind": "file.read", "detail": {"path": "/w/home/.config/gcloud/application_default_credentials.json"}}
    cap_g, _ = classify(e_gcloud)
    assert cap_g == "fs_read_sensitive"

    e_docker = {"kind": "file.read", "detail": {"path": "/w/home/.docker/config.json"}}
    cap_d, _ = classify(e_docker)
    assert cap_d == "fs_read_sensitive"


def test_toolchain_run_error_coverage_and_inconclusive(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "run.error", "detail": {"message": "Execution timeout after 30s"}, "outcome": "unknown",
         "attributed_to": "toolchain", "evidence": {"layer": "audit", "file": "runner.py", "line": 100}}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"]["install_completed"] = True
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert fp["coverage"]["run_error"] is True
    assert fp["coverage"]["run_timeout"] is True
    assert any("Error during call" in no for no in fp["coverage"]["not_observed"])

    v = evaluate(fp, claims)
    # A sole call-phase run.error with install_completed true is INCONCLUSIVE/REVIEW, never BENIGN
    assert v["verdict"] == "INCONCLUSIVE"
    assert v["action"] == "REVIEW"


def test_run_error_with_canary_or_two_strong_classes_stays_block(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.connect", "detail": {"dest": "198.51.100.1:80", "canary_in_bytes": True},
         "outcome": "blocked", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "run.error", "detail": {"message": "Timeout"}, "outcome": "unknown",
         "attributed_to": "toolchain", "evidence": {"layer": "audit", "file": "runner.py", "line": 100}}
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "MALICIOUS-EVIDENT"
    assert v["action"] == "BLOCK"


def test_env_differential_rules_ci_and_clock_only(tmp_path):
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))

    # Case 1: Dev-only behavior -> NO env_differential
    raw_dev = tmp_path / "raw_dev.jsonl"
    events_dev = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.connect", "detail": {"dest": "198.51.100.5:80"}, "outcome": "blocked", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 1}}
    ]
    raw_dev.write_text("\n".join(json.dumps(e) for e in events_dev) + "\n")
    fp_dev = build_fingerprint(str(raw_dev), meta, claims["package"])
    v_dev = evaluate(fp_dev, claims)
    assert not any(f["rule"] == "env_differential" for f in v_dev["findings"])

    # Case 2: Present in CI and not dev -> YES env_differential
    raw_ci = tmp_path / "raw_ci.jsonl"
    events_ci = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "net.connect", "detail": {"dest": "198.51.100.5:80"}, "outcome": "blocked", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 1}}
    ]
    raw_ci.write_text("\n".join(json.dumps(e) for e in events_ci) + "\n")
    fp_ci = build_fingerprint(str(raw_ci), meta, claims["package"])
    v_ci = evaluate(fp_ci, claims)
    assert any(f["rule"] == "env_differential" for f in v_ci["findings"])

    # Case 3: Present in clock+30d and not default -> YES env_differential
    raw_clock = tmp_path / "raw_clock.jsonl"
    events_clock = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "clock+30d",
         "kind": "net.connect", "detail": {"dest": "198.51.100.5:80"}, "outcome": "blocked", "attributed_to": "pkg",
         "evidence": {"layer": "audit", "file": "app.py", "line": 1}}
    ]
    raw_clock.write_text("\n".join(json.dumps(e) for e in events_clock) + "\n")
    fp_clock = build_fingerprint(str(raw_clock), meta, claims["package"])
    v_clock = evaluate(fp_clock, claims)
    assert any(f["rule"] == "env_differential" for f in v_clock["findings"])


def test_info_signal_class_score_zero_not_suspicious(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 1}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 1}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    f_info = [f for f in v["findings"] if f["signal_class"] == "info"]
    assert f_info
    assert f_info[0]["score"] == 0.0
    assert f_info[0]["severity"] == "info"
    assert v["verdict"] == "BENIGN-CONSISTENT"
    assert v["verdict"] != "SUSPICIOUS"


def test_short_readme_under_20_chars_unknown_intent(tmp_path):
    p = tmp_path / "pkg_short"
    p.mkdir()
    (p / "README.md").write_text("Short.")
    (p / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_short', version='1.0', classifiers=['Topic :: Internet :: WWW/HTTP'], entry_points={'console_scripts': ['tool=pkg:main']})\n")
    c = extract_claims(str(p))
    # Item 6: if cleaned README < 20 characters, unknown_intent is true and claims [] even with metadata
    assert c["unknown_intent"] is True
    assert c["claims"] == []
    assert c["intents"] == []


def test_short_readme_false_pass_regression(tmp_path):
    p = tmp_path / "pkg_false_pass"
    p.mkdir()
    (p / "README.md").write_text("Hi")
    (p / "pyproject.toml").write_text("""[project]
name = "pkg_false_pass"
version = "0.1.0"
description = "An HTTP client for widgets"

[project.scripts]
mytool = "pkg_false_pass:main"
""")
    claims = extract_claims(str(p))
    assert claims["unknown_intent"] is True
    assert claims["claims"] == []
    assert claims["intents"] == []

    # call-phase dyn.exec of data = open('/root/.ssh/id_rsa').read() on dev and ci
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5},
         "canary_match": []},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5},
         "canary_match": []},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events))
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert "decoded_exec" in v["independent_signals"]
    assert v["verdict"] != "BENIGN-CONSISTENT"

    # Also verify network attempt is unlicensed when README is short
    net_events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.http", "detail": {"url": "http://198.51.100.1/api"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 6},
         "canary_match": []},
    ]
    raw_net = tmp_path / "raw_net.jsonl"
    raw_net.write_text("\n".join(json.dumps(e) for e in net_events))
    fp_net = build_fingerprint(str(raw_net), meta, claims["package"])
    v_net = evaluate(fp_net, claims)
    assert any(f["rule"] == "network_unclaimed" or f["id"] == "network_unclaimed" for f in v_net["findings"])
    assert "network_unclaimed" in v_net["independent_signals"]


def test_inconclusive_summary_no_safe_word(tmp_path):
    raw = tmp_path / "raw.jsonl"
    raw.write_text("")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    meta["coverage"]["install_completed"] = False
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "INCONCLUSIVE"
    assert "safe" not in v["summary"].lower()


def test_probe_env_hostname_processors_display():
    from trustlens.fingerprint.normalize import classify
    cap_h, _ = classify({"kind": "env.read", "detail": {"name": "HOSTNAME"}})
    assert cap_h == "sandbox_probe"

    cap_p, _ = classify({"kind": "env.read", "detail": {"name": "NUMBER_OF_PROCESSORS"}})
    assert cap_p == "sandbox_probe"

    cap_d, _ = classify({"kind": "env.read", "detail": {"name": "DISPLAY"}})
    assert cap_d is None


def test_download_exec_net_http_then_dyn_exec(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.http", "detail": {"url": "http://payload.invalid/stage.py", "method": "GET"},
         "outcome": "blocked", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"co_filename": "<string>", "decoded_snippet": "print('stage2')"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 6}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    # Dynamic exec preceded by net.http in same profile+variant becomes download_exec
    dyn_ev = [e for e in fp["events"] if e["seq"] == 1][0]
    assert dyn_ev["capability"] == "download_exec"
    v = evaluate(fp, claims)
    assert any(f["signal_class"] == "dropper" for f in v["findings"])


def test_dedupe_key_does_not_collapse_compile_and_exec(tmp_path):
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.compile", "detail": {"decoded_snippet": "print(1)"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 1}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"co_filename": "<string>", "decoded_snippet": "print(2)"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 2}},
        {"seq": 2, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"co_filename": "<string>", "decoded_snippet": "print(2)"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"layer": "audit", "file": "app.py", "line": 2}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(raw), meta, claims["package"])
    # compile and exec must NOT collapse into each other
    assert len(fp["events"]) == 2
    # identical exec events collapse with count 2
    exec_ev = fp["events"][1]
    assert exec_ev["count"] == 2


def test_no_verdict_finding_with_empty_events():
    meta = json.loads((EXAMPLES / "clean_slug" / "run_meta.json").read_text())
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    fp = build_fingerprint(str(EXAMPLES / "clean_slug" / "raw_events.jsonl"), meta, claims["package"],
                           static_signals=[{"source": "guarddog", "rule": "shady-links"}])
    v = evaluate(fp, claims)
    for f in v["findings"]:
        assert len(f["events"]) > 0


def test_recorded_sandbox_packages():
    RECORDED = ROOT / "tests" / "sandbox" / "recorded"
    DATA = ROOT / "tests" / "sandbox" / "data"
    for name in ["hostname_gate", "clock_gate", "github_gate", "pth_toy"]:
        raw_path = RECORDED / name / "raw_events.jsonl"
        meta = json.loads((RECORDED / name / "run_meta.json").read_text())
        pkg_dir = DATA / name
        claims = extract_claims(str(pkg_dir))
        fp = build_fingerprint(str(raw_path), meta, claims["package"])
        v = evaluate(fp, claims)
        assert v["verdict"] == "MALICIOUS-EVIDENT", f"{name} expected MALICIOUS-EVIDENT, got {v['verdict']}"
        assert v["action"] == "BLOCK"

    # cli_toy test:
    cli_raw = RECORDED / "cli_toy" / "raw_events.jsonl"
    cli_meta = json.loads((RECORDED / "cli_toy" / "run_meta.json").read_text())
    cli_pkg = DATA / "cli_toy"
    cli_claims = extract_claims(str(cli_pkg))
    cli_fp = build_fingerprint(str(cli_raw), cli_meta, cli_claims["package"])
    cli_v = evaluate(cli_fp, cli_claims)
    assert cli_v["verdict"] == "MALICIOUS-EVIDENT"
    assert cli_v["action"] == "BLOCK"
    env_diff_findings = [f for f in cli_v["findings"] if f["rule"] == "env_differential"]
    assert not any("install_hook" in f["title"] or "install_hook" in f["explanation"] for f in env_diff_findings)


def test_r4_shim_secret_access_not_benign(tmp_path):
    # Regression test for Bug 1:
    # 1. long README (>= 20 chars) + [project.scripts] console script + dyn.exec decoded_snippet "data = open('/root/.ssh/id_rsa').read()"
    p1 = tmp_path / "pkg_cli_secret"
    p1.mkdir()
    (p1 / "README.md").write_text("This is a command line utility package with long description.")
    (p1 / "pyproject.toml").write_text("""[project]
name = "pkg_cli_secret"
version = "0.1.0"
description = "A CLI tool"

[project.scripts]
mytool = "pkg_cli_secret:main"
""")
    claims1 = extract_claims(str(p1))
    assert claims1["unknown_intent"] is False
    assert any(i["intent"] == "cli_tool" for i in claims1["intents"])

    raw1 = tmp_path / "raw1.jsonl"
    events1 = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
    ]
    raw1.write_text("\n".join(json.dumps(e) for e in events1) + "\n")
    meta1 = {
        "schema_version": "1.0",
        "package": claims1["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp1 = build_fingerprint(str(raw1), meta1, claims1["package"])
    v1 = evaluate(fp1, claims1)
    assert "decoded_exec" in v1["independent_signals"]
    assert v1["verdict"] != "BENIGN-CONSISTENT"

    # 2. README "Hi" (unknown_intent true, claims [], intents []) + dyn.exec snippet "class TemplateShim:\n    data = open('/root/.ssh/id_rsa').read()"
    p2 = tmp_path / "pkg_template_secret"
    p2.mkdir()
    (p2 / "README.md").write_text("Hi")
    (p2 / "pyproject.toml").write_text("""[project]
name = "pkg_template_secret"
version = "0.1.0"
description = "A utility"
""")
    claims2 = extract_claims(str(p2))
    assert claims2["unknown_intent"] is True
    assert claims2["claims"] == []
    assert claims2["intents"] == []

    raw2 = tmp_path / "raw2.jsonl"
    events2 = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
    ]
    raw2.write_text("\n".join(json.dumps(e) for e in events2) + "\n")
    meta2 = {
        "schema_version": "1.0",
        "package": claims2["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp2 = build_fingerprint(str(raw2), meta2, claims2["package"])
    v2 = evaluate(fp2, claims2)
    assert "decoded_exec" in v2["independent_signals"]
    assert v2["verdict"] != "BENIGN-CONSISTENT"

    # 3. same ssh snippet attributed_to "dep:jinja2" with no TemplateShim text
    raw3 = tmp_path / "raw3.jsonl"
    events3 = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"file": "jinja2/compiler.py", "line": 50}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "data = open('/root/.ssh/id_rsa').read()"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"file": "jinja2/compiler.py", "line": 50}},
    ]
    raw3.write_text("\n".join(json.dumps(e) for e in events3) + "\n")
    fp3 = build_fingerprint(str(raw3), meta1, claims1["package"])
    v3 = evaluate(fp3, claims1)
    assert "decoded_exec" in v3["independent_signals"]
    assert v3["verdict"] != "BENIGN-CONSISTENT"


def test_r4_benign_cases_stay_benign_consistent(tmp_path):
    p = tmp_path / "pkg_cli_benign"
    p.mkdir()
    (p / "README.md").write_text("This is a command line utility package with long description.")
    (p / "pyproject.toml").write_text("""[project]
name = "pkg_cli_benign"
version = "0.1.0"
description = "A CLI tool"

[project.scripts]
mytool = "pkg_cli_benign:main"
""")
    claims = extract_claims(str(p))

    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "print('hello from the tool')"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "print('hello from the tool')"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert "decoded_exec" not in v["independent_signals"]
    assert v["verdict"] == "BENIGN-CONSISTENT"
    assert v["score"] == 0
    assert any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" and f["score"] == 0 for f in v["findings"])


@pytest.mark.parametrize("secret_keyword", [
    ".ssh/", "id_rsa", ".aws/", ".npmrc", ".pypirc",
    ".git-credentials", ".netrc", ".kube/", "/etc/shadow", ".gnupg/",
    ".SSH/", "ID_RSA", ".AWS/",
])
def test_r4_all_secret_patterns_detected(tmp_path, secret_keyword):
    p = tmp_path / "pkg_sec"
    p.mkdir(exist_ok=True)
    (p / "README.md").write_text("This is a command line utility package with long description.")
    (p / "pyproject.toml").write_text("""[project]
name = "pkg_sec"
version = "0.1.0"
description = "A CLI tool"

[project.scripts]
mytool = "pkg_sec:main"
""")
    claims = extract_claims(str(p))
    raw = tmp_path / f"raw_{abs(hash(secret_keyword))}.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": f"open('/path/{secret_keyword}/target').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": f"open('/path/{secret_keyword}/target').read()"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert "decoded_exec" in v["independent_signals"]
    assert v["verdict"] != "BENIGN-CONSISTENT"


def test_timeout_in_event_detail_not_inconclusive(tmp_path):
    # Regression test for Bug 2:
    # A rest_wrapper-style package (network and env_secrets claimed) whose only events are
    # net.http url "https://example.invalid/v1/timeout" on dev and ci, full coverage,
    # must return BENIGN-CONSISTENT (not INCONCLUSIVE).
    claims = extract_claims(str(BENCH / "clean/rest_wrapper"))
    raw = tmp_path / "raw.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.http", "detail": {"url": "https://example.invalid/v1/timeout"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "rest_wrapper/__init__.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "net.http", "detail": {"url": "https://example.invalid/v1/timeout"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "rest_wrapper/__init__.py", "line": 10}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert not fp["coverage"].get("run_error")
    assert not fp["coverage"].get("run_timeout")
    v = evaluate(fp, claims)
    assert v["verdict"] == "BENIGN-CONSISTENT"
    assert v["action"] == "PASS"


def test_install_note_real_timeout_is_inconclusive(tmp_path):
    raw = tmp_path / "raw.jsonl"
    raw.write_text("")
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install"], "install_completed": False,
                     "install_note": "Build timeout reached during wheel compilation",
                     "callables_total": 0, "callables_exercised": 0, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "INCONCLUSIVE"
    assert v["action"] == "REVIEW"


@pytest.mark.parametrize("secret_snippet", [
    "open('/etc/passwd').read()",
    "open('/root/.docker/config.json').read()",
    "open('/root/.config/gcloud/application_default_credentials.json').read()",
    "x = os.environ['AWS_SECRET_ACCESS_KEY']",
    "x = os.environ.get('GITHUB_TOKEN')",
])
def test_regression_shim_denylist_reuses_normalizer_patterns(tmp_path, secret_snippet):
    # Hole 1: cli_tool shim or dep TemplateShim accessing secrets must be decoded_exec (strong)
    p = tmp_path / f"pkg_cli_{abs(hash(secret_snippet))}"
    p.mkdir()
    (p / "README.md").write_text("This is a command line tool with long descriptive text.")
    (p / "pyproject.toml").write_text("""[project]
name = "cli_tool_pkg"
version = "0.1.0"
description = "A CLI tool"

[project.scripts]
mytool = "cli_tool_pkg:main"
""")
    claims = extract_claims(str(p))
    raw = tmp_path / f"raw_{abs(hash(secret_snippet))}.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": secret_snippet},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": secret_snippet},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "pkg/__init__.py", "line": 5}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert "decoded_exec" in v["independent_signals"]
    assert v["verdict"] != "BENIGN-CONSISTENT"

    # Also test dep:jinja2 TemplateShim reading GITHUB_TOKEN
    raw_dep = tmp_path / f"raw_dep_{abs(hash(secret_snippet))}.jsonl"
    events_dep = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    token = os.environ.get('GITHUB_TOKEN')"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"file": "jinja2/compiler.py", "line": 50}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    token = os.environ.get('GITHUB_TOKEN')"},
         "outcome": "succeeded", "attributed_to": "dep:jinja2", "evidence": {"file": "jinja2/compiler.py", "line": 50}},
    ]
    raw_dep.write_text("\n".join(json.dumps(e) for e in events_dep) + "\n")
    fp_dep = build_fingerprint(str(raw_dep), meta, claims["package"])
    v_dep = evaluate(fp_dep, claims)
    assert "decoded_exec" in v_dep["independent_signals"]
    assert v_dep["verdict"] != "BENIGN-CONSISTENT"


def test_regression_shim_canary_hit_not_benign_or_info(tmp_path):
    # Hole 2: dep:jinja2 TemplateShim pass with canary_match ["ssh_key"] on dev and ci must not be info or BENIGN-CONSISTENT
    raw = tmp_path / "raw_canary_shim.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "dep:jinja2",
         "evidence": {"file": "jinja2/compiler.py", "line": 50}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "dyn.exec", "detail": {"decoded_snippet": "class TemplateShim:\n    pass\n"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "dep:jinja2",
         "evidence": {"file": "jinja2/compiler.py", "line": 50}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert fp["events"][0]["canary_hit"] is True
    v = evaluate(fp, claims)
    assert not any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" for f in v["findings"])
    assert "decoded_exec" in v["independent_signals"]
    assert v["verdict"] != "BENIGN-CONSISTENT"


def test_regression_canary_on_non_sensitive_path_never_dropped(tmp_path):
    # Hole 3: file.read /tmp/not-sensitive.txt with canary_match ["ssh_key"] kept and mapped to fs_read_sensitive
    raw = tmp_path / "raw_canary_nonsensitive.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "file.read", "detail": {"path": "/tmp/not-sensitive.txt"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"file": "app.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "file.read", "detail": {"path": "/tmp/not-sensitive.txt"},
         "canary_match": ["ssh_key"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"file": "app.py", "line": 10}},
        {"seq": 2, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "env.read", "detail": {"name": "MY_CUSTOM_VAR"},
         "canary_match": ["env_canary"], "outcome": "succeeded", "attributed_to": "pkg",
         "evidence": {"file": "app.py", "line": 11}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    assert len(fp["events"]) == 3
    assert fp["events"][0]["capability"] == "fs_read_sensitive"
    assert fp["events"][0]["canary_hit"] is True
    assert fp["events"][2]["capability"] == "env_secrets"
    assert fp["events"][2]["canary_hit"] is True
    v = evaluate(fp, claims)
    assert v["verdict"] != "BENIGN-CONSISTENT"


def test_regression_url_in_install_note_not_inconclusive(tmp_path):
    # Hole 4: URL in install note does not flip rest_wrapper to INCONCLUSIVE
    claims = extract_claims(str(BENCH / "clean/rest_wrapper"))
    raw = tmp_path / "raw_url_note.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "net.http", "detail": {"url": "https://example.invalid/v1/timeout"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "rest_wrapper/__init__.py", "line": 10}},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "kind": "net.http", "detail": {"url": "https://example.invalid/v1/timeout"},
         "outcome": "succeeded", "attributed_to": "pkg", "evidence": {"file": "rest_wrapper/__init__.py", "line": 10}},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": {"phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
                     "triggers_run": ["install", "import", "call_all"], "install_completed": True,
                     "install_note": "log line mentioned https://example.invalid/v1/timeout",
                     "callables_total": 1, "callables_exercised": 1, "not_observed": []},
    }
    fp = build_fingerprint(str(raw), meta, claims["package"])
    v = evaluate(fp, claims)
    assert v["verdict"] == "BENIGN-CONSISTENT"
    assert v["action"] == "PASS"

    # Real timeout still flips to INCONCLUSIVE
    meta_real_timeout = dict(meta)
    meta_real_timeout["coverage"] = dict(meta["coverage"], install_note="command timed out after 30s")
    fp_real = build_fingerprint(str(raw), meta_real_timeout, claims["package"])
    v_real = evaluate(fp_real, claims)
    assert v_real["verdict"] == "INCONCLUSIVE"
    assert v_real["action"] == "REVIEW"


def test_regression_no_crashes_on_malformed_inputs_and_coverage_isolation(tmp_path):
    # Hole 5: detail null, missing kind, static_signals null, unknown capability, caller coverage isolation
    raw = tmp_path / "raw_malformed.jsonl"
    events = [
        {"seq": 0, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
         "kind": "dyn.exec", "detail": None, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 1, "phase": "call", "trigger": "call_all", "profile": "ci", "variant": "default",
         "detail": {"something": 123}, "outcome": "succeeded", "attributed_to": "pkg"},
        {"seq": 2, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
         "kind": "run.error", "detail": {"message": "Execution timeout after 30s"}, "attributed_to": "toolchain"},
    ]
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    orig_coverage = {
        "phases_run": ["install", "import", "call"], "profiles_run": ["dev", "ci"], "variants_run": ["default"],
        "triggers_run": ["install", "import", "call_all"], "install_completed": True,
        "callables_total": 1, "callables_exercised": 1, "not_observed": ["phase_x"],
    }
    meta = {
        "schema_version": "1.0",
        "package": claims["package"],
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": orig_coverage,
    }
    # Run build_fingerprint with static_signals=None
    fp = build_fingerprint(str(raw), meta, claims["package"], static_signals=None)

    # Verify coverage dict isolation: orig_coverage was copied and not mutated
    assert "run_error" not in orig_coverage
    assert "run_timeout" not in orig_coverage
    assert orig_coverage["not_observed"] == ["phase_x"]
    assert fp["coverage"]["run_error"] is True
    assert fp["coverage"]["run_timeout"] is True

    # Inject unknown capability event into fingerprint
    fp["events"].append({
        "id": "ev99", "seq": 99, "phase": "call", "trigger": "call_all", "profile": "dev", "variant": "default",
        "capability": "alien_telepathy", "detail": {}, "canary_hit": False, "canary_ids": [],
        "outcome": "succeeded", "attributed_to": "pkg", "evidence": {},
    })
    # Evaluate with static_signals=None coerced in fp
    fp["static_signals"] = None
    v = evaluate(fp, claims)
    assert v["verdict"] in ("BENIGN-CONSISTENT", "SUSPICIOUS", "MALICIOUS-EVIDENT", "INCONCLUSIVE")
    assert any("alien_telepathy" in f["title"] for f in v["findings"])


def _full_meta(package, **coverage_extra):
    coverage = {
        "phases_run": ["install", "import", "call"],
        "profiles_run": ["dev", "ci"],
        "variants_run": ["default"],
        "triggers_run": ["install", "import", "call_all"],
        "install_completed": True,
        "callables_total": 1,
        "callables_exercised": 1,
        "not_observed": [],
    }
    coverage.update(coverage_extra)
    return {
        "schema_version": "1.0",
        "package": package,
        "run": {"started_at": 1, "finished_at": 2, "sandbox": "bwrap", "timeout_s": 30},
        "coverage": coverage,
    }


def _pair(kind, detail, *, phase="call", attributed="pkg", canary=None, seq0=0):
    rows = []
    for offset, profile in enumerate(("dev", "ci")):
        row = {
            "seq": seq0 + offset, "phase": phase,
            "trigger": "install" if phase == "install" else "call_all",
            "profile": profile, "variant": "default", "kind": kind, "detail": detail,
            "outcome": "succeeded", "attributed_to": attributed,
            "evidence": {"file": "pkg/__init__.py", "line": 1},
        }
        if canary is not None:
            row["canary_match"] = canary
        rows.append(row)
    return rows


def _pipeline(tmp_path, claims, events, **coverage_extra):
    raw = tmp_path / "raw.jsonl"
    raw.write_text("\n".join(json.dumps(e) for e in events) + ("\n" if events else ""))
    meta = _full_meta(claims["package"], **coverage_extra)
    before = json.dumps(meta, sort_keys=True)
    fp = build_fingerprint(str(raw), meta, claims["package"])
    verdict = evaluate(fp, claims)
    assert json.dumps(meta, sort_keys=True) == before
    return fp, verdict


def _pkg(tmp_path, name, readme, toml_extra=""):
    root = tmp_path / name
    root.mkdir()
    (root / "README.md").write_text(readme)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "0.1.0"\ndescription = "demo"\n{toml_extra}'
    )
    return extract_claims(str(root))


def test_regression_loose_secret_scan_does_not_block(tmp_path):
    # 'for key, value' used to match SECRET_ENV and turn one unclaimed request into a false BLOCK.
    claims = _pkg(
        tmp_path, "cli_tool_pkg",
        "This is a command line utility package with a long description.\n",
        '\n[project.scripts]\nmytool = "cli_tool_pkg:main"\n',
    )
    assert claims["unknown_intent"] is False
    assert any(i["intent"] == "cli_tool" for i in claims["intents"])
    events = _pair("dyn.exec", {"decoded_snippet": "for key, value in items:\n    pass"})
    events += _pair("net.http", {"url": "https://example.invalid/v1/x"}, seq0=2)
    _fp, verdict = _pipeline(tmp_path, claims, events)
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["action"] == "REVIEW"
    assert verdict["score"] == 2.4
    assert verdict["independent_signals"] == ["network_unclaimed"]
    assert any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" and f["score"] == 0 for f in verdict["findings"])


@pytest.mark.parametrize("snippet", [
    "token = None",
    "for key, value in items:\n    pass",
    "GITHUB_ACTIONS",
    "os.environ.get('GITHUB_ACTIONS')",
    "print('hello from the tool')",
    "class TemplateShim:\n    pass\n",
    "open('/opt/valid_rsa')",
    "json.load(open('config.json'))",
    "import logging\npassword='x'\nlogging.info('started')",
    "import argparse\np = argparse.ArgumentParser()\np.add_argument('--token', help='API token')",
])
def test_regression_benign_snippets_stay_score_zero(tmp_path, snippet):
    claims = _pkg(
        tmp_path, "cli_tool_pkg",
        "This is a command line utility package with a long description.\n",
        '\n[project.scripts]\nmytool = "cli_tool_pkg:main"\n',
    )
    _fp, verdict = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert verdict["verdict"] == "BENIGN-CONSISTENT"
    assert verdict["score"] == 0
    assert "decoded_exec" not in verdict["independent_signals"]


def test_regression_plain_pth_path_stays_score_zero(tmp_path):
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    _fp, verdict = _pipeline(
        tmp_path, claims,
        _pair("startup.pth", {"file": "plain.pth", "line_text": "/opt/custom/path"}, phase="install"),
    )
    assert verdict["verdict"] == "BENIGN-CONSISTENT"
    assert verdict["score"] == 0
    assert "startup_hook" not in verdict["independent_signals"]


@pytest.mark.parametrize("snippet", [
    "open('/etc/passwd')",
    "open('/root/.docker/config.json')",
    "open('/root/.config/gcloud/application_default_credentials.json')",
    "os.environ['AWS_SECRET_ACCESS_KEY']",
    "os.environ.get('GITHUB_TOKEN')",
    "os.getenv('GITHUB_TOKEN')",
])
def test_regression_secret_snippets_stay_suspicious(tmp_path, snippet):
    claims = _pkg(
        tmp_path, "cli_tool_pkg",
        "This is a command line utility package with a long description.\n",
        '\n[project.scripts]\nmytool = "cli_tool_pkg:main"\n',
    )
    _fp, verdict = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert verdict["verdict"] == "SUSPICIOUS"
    assert "decoded_exec" in verdict["independent_signals"]

    dep_snippet = "class TemplateShim:\n    " + snippet
    _fp_dep, verdict_dep = _pipeline(
        tmp_path, claims,
        _pair("dyn.exec", {"decoded_snippet": dep_snippet}, attributed="dep:jinja2"),
    )
    assert verdict_dep["verdict"] == "SUSPICIOUS"
    assert "decoded_exec" in verdict_dep["independent_signals"]
    assert not any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" for f in verdict_dep["findings"])


def test_regression_ssh_id_rsa_snippet_stays_non_benign(tmp_path):
    claims = _pkg(
        tmp_path, "cli_tool_pkg",
        "This is a command line utility package with a long description.\n",
        '\n[project.scripts]\nmytool = "cli_tool_pkg:main"\n',
    )
    snippet = "open('/root/.ssh/id_rsa')"
    _fp, verdict = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert verdict["verdict"] != "BENIGN-CONSISTENT"
    assert "decoded_exec" in verdict["independent_signals"]
    dep = "class TemplateShim:\n    " + snippet
    _fp_dep, verdict_dep = _pipeline(
        tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": dep}, attributed="dep:jinja2"),
    )
    assert verdict_dep["verdict"] != "BENIGN-CONSISTENT"
    assert "decoded_exec" in verdict_dep["independent_signals"]


def test_regression_canary_write_keeps_persistence(tmp_path):
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    events = _pair("file.write", {"path": "/w/home/.bashrc"}, phase="call", canary=["ssh_key"])
    events += _pair(
        "startup.pth", {"file": "x.pth", "line_text": "import os; os.system('x')"},
        phase="install", seq0=2,
    )
    fp, verdict = _pipeline(tmp_path, claims, events)
    assert {e["capability"] for e in fp["events"] if e["detail"].get("path", "").endswith(".bashrc")} == {"persistence"}
    assert all(e["canary_hit"] for e in fp["events"] if e["capability"] == "persistence")
    assert verdict["verdict"] == "MALICIOUS-EVIDENT"
    assert verdict["action"] == "BLOCK"
    assert verdict["score"] == 17.6
    assert set(verdict["independent_signals"]) == {"persistence", "startup_hook"}

    new_fp, _new_verdict = _pipeline(
        tmp_path, claims,
        _pair("file.new", {"path": "/w/home/.bashrc"}, phase="call", canary=["ssh_key"]),
    )
    assert {e["capability"] for e in new_fp["events"]} == {"persistence"}

    read_fp, read_verdict = _pipeline(
        tmp_path, claims,
        _pair("file.read", {"path": "/tmp/not-sensitive.txt"}, canary=["ssh_key"]),
    )
    assert {e["capability"] for e in read_fp["events"]} == {"fs_read_sensitive"}
    assert all(e["canary_hit"] for e in read_fp["events"])
    assert read_verdict["verdict"] != "BENIGN-CONSISTENT"


def test_regression_claimed_canary_does_not_pass(tmp_path):
    ssh = _pkg(tmp_path, "sshpkg", "An ssh client and key management helper for local hosts and servers.\n")
    assert any(i["intent"] == "ssh_tool" for i in ssh["intents"])
    assert any(c["capability"] == "fs_read_sensitive" for c in ssh["claims"])
    _fp, quiet = _pipeline(tmp_path, ssh, _pair("file.read", {"path": "/w/home/.ssh/id_rsa"}))
    assert quiet["verdict"] == "BENIGN-CONSISTENT"
    assert quiet["score"] == 0
    _fp, hit = _pipeline(
        tmp_path, ssh, _pair("file.read", {"path": "/w/home/.ssh/id_rsa"}, canary=["ssh_key"]),
    )
    assert hit["verdict"] == "SUSPICIOUS"
    assert hit["action"] == "REVIEW"
    assert hit["score"] == 7.2
    assert any(f["canary_hit"] and f["capability"] == "fs_read_sensitive" for f in hit["findings"])

    cfg = _pkg(
        tmp_path, "cfgpkg",
        "A configuration loader that reads each environment variable for service settings.\n",
    )
    assert any(i["intent"] == "config_loader" for i in cfg["intents"])
    _fp, cfg_quiet = _pipeline(tmp_path, cfg, _pair("env.read", {"name": "AWS_SECRET_ACCESS_KEY"}))
    assert cfg_quiet["verdict"] == "BENIGN-CONSISTENT"
    _fp, cfg_hit = _pipeline(
        tmp_path, cfg, _pair("env.read", {"name": "AWS_SECRET_ACCESS_KEY"}, canary=["aws_secret_env"]),
    )
    assert cfg_hit["verdict"] == "SUSPICIOUS"
    assert cfg_hit["action"] == "REVIEW"
    assert cfg_hit["score"] == 6.0


@pytest.mark.parametrize("note", [
    "log line mentioned https://example.invalid/v1/timeout",
    "log line mentioned HTTPS://example.invalid/v1/TIMEOUT",
    "completed with no timeout",
])
def test_regression_install_note_url_or_negation_stays_benign(tmp_path, note):
    claims = extract_claims(str(BENCH / "clean/rest_wrapper"))
    events = _pair("net.http", {"url": "https://example.invalid/v1/timeout"})
    _fp, verdict = _pipeline(tmp_path, claims, events, install_note=note)
    assert verdict["verdict"] == "BENIGN-CONSISTENT"
    assert verdict["action"] == "PASS"


def test_regression_net_http_timeout_url_stays_benign(tmp_path):
    claims = extract_claims(str(BENCH / "clean/rest_wrapper"))
    _fp, verdict = _pipeline(
        tmp_path, claims, _pair("net.http", {"url": "https://example.invalid/v1/timeout"}),
    )
    assert not _fp["coverage"].get("run_timeout")
    assert verdict["verdict"] == "BENIGN-CONSISTENT"
    assert verdict["score"] == 0


@pytest.mark.parametrize("note", [
    "Execution timeout after 30s",
    "command timed out after 30s",
    "TimeoutError: deadline exceeded",
    "hit a time-out during install",
])
def test_regression_install_note_real_timeout_phrases(tmp_path, note):
    claims = extract_claims(str(BENCH / "clean/rest_wrapper"))
    events = _pair("net.http", {"url": "https://example.invalid/v1/ok"})
    _fp, verdict = _pipeline(tmp_path, claims, events, install_note=note)
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert verdict["action"] == "REVIEW"


def _cli_claims(tmp_path):
    return _pkg(
        tmp_path, "cli_tool_pkg",
        "This is a command line utility package with a long description.\n",
        '\n[project.scripts]\nmytool = "cli_tool_pkg:main"\n',
    )


@pytest.mark.parametrize("snippet", [
    "pathlib.Path.home()/'.aws'/'credentials'",
    "pathlib.Path.home() / '.aws' / 'credentials'",
    "open('/et'+'c/passwd')",
    "open('/et' + 'c/passwd')",
    "open('~/.aws/credentials')",
    "pathlib.Path.home()/'.ssh'/'id_rsa'",
    "open('/root/'+'.ssh/id_rsa')",
    "getattr(os,'environ')['AWS_SECRET_ACCESS_KEY']",
    'getattr(os, "environ")["AWS_SECRET_ACCESS_KEY"]',
    "subprocess.run(['cat','/etc/shadow'])",
])
def test_regression_split_literal_secrets_are_suspicious(tmp_path, snippet):
    # Split markers and path joins must stay decoded_exec in cli_tool and dep TemplateShim contexts.
    claims = _cli_claims(tmp_path)
    _fp, verdict = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["action"] == "REVIEW"
    assert verdict["score"] == 10.8
    assert verdict["independent_signals"] == ["decoded_exec"]

    dep = "class TemplateShim:\n    " + snippet
    _fp_dep, verdict_dep = _pipeline(
        tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": dep}, attributed="dep:jinja2"),
    )
    assert verdict_dep["verdict"] == "SUSPICIOUS"
    assert verdict_dep["action"] == "REVIEW"
    assert verdict_dep["score"] == 7.56
    assert verdict_dep["independent_signals"] == ["decoded_exec"]
    assert not any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" for f in verdict_dep["findings"])


@pytest.mark.parametrize("snippet", [
    "os.environ.get('SSH_AUTH_SOCK')",
    "os.environ.get('AWS_DEFAULT_REGION')",
    "os.environ.get('AWS_REGION')",
    "TOKEN = None",
    "for KEY, value in items: pass",
    "help='Set API_KEY'",
])
def test_regression_nonsecret_caps_do_not_block(tmp_path, snippet):
    # All-caps non-secrets and bare tokens are BENIGN alone, and only network_unclaimed with one request.
    claims = _cli_claims(tmp_path)
    _fp, alone = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert alone["verdict"] == "BENIGN-CONSISTENT"
    assert alone["action"] == "PASS"
    assert alone["score"] == 0
    assert alone["independent_signals"] == []

    events = _pair("dyn.exec", {"decoded_snippet": snippet})
    events += _pair("net.http", {"url": "https://example.invalid"}, seq0=2)
    _fp_net, with_net = _pipeline(tmp_path, claims, events)
    assert with_net["verdict"] == "SUSPICIOUS"
    assert with_net["action"] == "REVIEW"
    assert with_net["score"] == 2.4
    assert with_net["independent_signals"] == ["network_unclaimed"]

    dep = "class TemplateShim:\n    " + snippet
    _fp_dep, verdict_dep = _pipeline(
        tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": dep}, attributed="dep:jinja2"),
    )
    assert verdict_dep["verdict"] == "BENIGN-CONSISTENT"
    assert verdict_dep["action"] == "PASS"
    assert verdict_dep["score"] == 0
    assert "decoded_exec" not in verdict_dep["independent_signals"]


@pytest.mark.parametrize("snippet", [
    "os.environ.get('AWS_SESSION_TOKEN')",
    "os.environ['GH_TOKEN']",
    "os.getenv('NPM_TOKEN')",
    "os.environ.get('PYPI_TOKEN')",
    "os.environ['GOOGLE_APPLICATION_CREDENTIALS']",
    "os.environ.get('MY_SERVICE_SECRET')",
    "os.environ['SERVICE_TOKEN']",
])
def test_regression_curated_env_reads_stay_suspicious(tmp_path, snippet):
    claims = _cli_claims(tmp_path)
    _fp, verdict = _pipeline(tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": snippet}))
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["action"] == "REVIEW"
    assert verdict["score"] == 10.8
    assert "decoded_exec" in verdict["independent_signals"]

    dep = "class TemplateShim:\n    " + snippet
    _fp_dep, verdict_dep = _pipeline(
        tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": dep}, attributed="dep:jinja2"),
    )
    assert verdict_dep["verdict"] == "SUSPICIOUS"
    assert "decoded_exec" in verdict_dep["independent_signals"]
    assert not any(f["rule"] == "decoded_exec" and f["signal_class"] == "info" for f in verdict_dep["findings"])


def _shim(snippet: str) -> str:
    return "class TemplateShim:\n    " + snippet


def _expect_secret_contexts(tmp_path, claims, snippet):
    """cli_tool pkg, pkg TemplateShim, and dep:jinja2 TemplateShim."""
    contexts = (
        ("pkg", snippet, 10.8),
        ("pkg", _shim(snippet), 10.8),
        ("dep:jinja2", _shim(snippet), 7.56),
    )
    for attributed, text, score in contexts:
        _fp, verdict = _pipeline(
            tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": text}, attributed=attributed),
        )
        assert verdict["verdict"] == "SUSPICIOUS", text
        assert verdict["action"] == "REVIEW", text
        assert verdict["score"] == score, text
        assert verdict["independent_signals"] == ["decoded_exec"], text
        assert not any(
            f["rule"] == "decoded_exec" and f["signal_class"] == "info" for f in verdict["findings"]
        ), text


def _expect_benign_contexts(tmp_path, claims, snippet):
    contexts = (
        ("pkg", snippet),
        ("pkg", _shim(snippet)),
        ("dep:jinja2", _shim(snippet)),
    )
    for attributed, text in contexts:
        _fp, alone = _pipeline(
            tmp_path, claims, _pair("dyn.exec", {"decoded_snippet": text}, attributed=attributed),
        )
        assert alone["verdict"] == "BENIGN-CONSISTENT", text
        assert alone["action"] == "PASS", text
        assert alone["score"] == 0, text
        assert alone["independent_signals"] == [], text
        events = _pair("dyn.exec", {"decoded_snippet": text}, attributed=attributed)
        events += _pair("net.http", {"url": "https://example.invalid"}, seq0=2)
        _fp_net, with_net = _pipeline(tmp_path, claims, events)
        assert with_net["verdict"] == "SUSPICIOUS", text
        assert with_net["action"] == "REVIEW", text
        assert with_net["score"] == 2.4, text
        assert with_net["independent_signals"] == ["network_unclaimed"], text


_SECRET_SNIPPETS = [
    "pathlib.Path.home()/'.aws'/'credentials'",
    "open('/et'+'c/passwd')",
    "open('~/.aws/credentials')",
    "pathlib.Path.home()/'.ssh'/'id_rsa'",
    "open('/root/'+'.ssh/id_rsa')",
    "getattr(os,'environ')['AWS_SECRET_ACCESS_KEY']",
    "subprocess.run(['cat','/etc/shadow'])",
    "open('/etc/passwd')",
    "open('/root/.docker/config.json')",
    "open('/root/.config/gcloud/application_default_credentials.json')",
    "os.environ['AWS_SECRET_ACCESS_KEY']",
    "os.environ.get('GITHUB_TOKEN')",
    "os.getenv('GITHUB_TOKEN')",
    "os.environ[f'AWS_SECRET_ACCESS_KEY']",
    "os.environ.get(f'GITHUB_TOKEN')",
    "os.getenv(f'NPM_TOKEN')",
    "os.environ.copy()['AWS_SECRET_ACCESS_KEY']",
    "dict(os.environ)['AWS_SECRET_ACCESS_KEY']",
    "from os import environ; environ['AWS_SECRET_ACCESS_KEY']",
    "open('/etc/' 'passwd')",
    "os.path.join('/etc','passwd')",
    # Regressions vs main found in verification: aliased os access and real secret names.
    "import os as o\no.environ['AWS_SECRET_ACCESS_KEY']",
    "import os as o\no.getenv('GITHUB_TOKEN')",
    "import sys, os as o\no.environ.get('DB_PASSWORD')",
    "from os import getenv\ngetenv('NPM_TOKEN')",
    "from os import getenv as g\ng('NPM_TOKEN')",
    "from os import environ as E\nE['AWS_SECRET_ACCESS_KEY']",
    "from os import (environ as e,\n    getenv)\ngetenv('GITHUB_TOKEN')",
    "__import__('os').environ['AWS_SECRET_ACCESS_KEY']",
    "os.environ['DB_PASSWORD']",
    "os.environ['PRIVATE_KEY']",
    "os.getenv('SSH_PRIVATE_KEY')",
    "os.getenv('MYSQL_PASSWD')",
    "os.getenv('SERVICE_CREDENTIALS')",
]

_BENIGN_SNIPPETS = [
    "os.environ.get('SSH_AUTH_SOCK')",
    "os.environ.get('AWS_DEFAULT_REGION')",
    "os.environ.get('AWS_REGION')",
    "os.environ[f'SSH_AUTH_SOCK']",
    "os.environ.get(f'AWS_REGION')",
    "os.environ.get('MY_TOKEN_COUNT')",
    "os.environ['MY_TOKEN_COUNT']",
    "MY_TOKEN_COUNT",
    "TOKEN = None",
    "TOKEN_LIMIT = 5",
    "for KEY, value in items: pass",
    "for KEY, value in items",
    "for key, value in items:\n    pass",
    "token = None",
    "secret_len",
    "help='Set API_KEY'",
    "help='SECRET_SAUCE'",
    "help='Use SECRET_SAUCE'",
    "GITHUB_ACTIONS",
    "os.environ.get('GITHUB_ACTIONS')",
    "open('/opt/valid_rsa')",
    "json.load(open('config.json'))",
    "import logging\npassword='x'\nlogging.info('started')",
    "import argparse\np = argparse.ArgumentParser()\np.add_argument('--token', help='API token')",
    "os.path.join('/opt', 'valid_rsa')",
    "print('not' 'a secret')",
    "import os as o\no.getenv('HOME')",
    "from os import environ as e\ne['HOME']",
    "from os import getenv\ngetenv('AWS_REGION')",
    "from os import getenv\nself.getenv('NPM_TOKEN')",
    "os.getenv('PRIMARY_KEYBOARD')",
    "os.getenv('SORT_KEYS')",
]


@pytest.mark.parametrize("snippet", _SECRET_SNIPPETS)
def test_regression_secret_snippets_all_contexts(tmp_path, snippet):
    claims = _cli_claims(tmp_path)
    _expect_secret_contexts(tmp_path, claims, snippet)


@pytest.mark.parametrize("snippet", _BENIGN_SNIPPETS)
def test_regression_benign_snippets_all_contexts(tmp_path, snippet):
    claims = _cli_claims(tmp_path)
    _expect_benign_contexts(tmp_path, claims, snippet)


def test_regression_run_timeout_and_run_error_are_inconclusive(tmp_path):
    claims = extract_claims(str(BENCH / "clean/clean_slug"))
    _fp, verdict = _pipeline(tmp_path, claims, [], run_timeout=True)
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert verdict["action"] == "REVIEW"

    for message in ("Execution timeout after 30s", "TimeoutError: deadline exceeded"):
        events = [{
            "seq": 0, "phase": "install", "trigger": "install", "profile": "dev", "variant": "default",
            "kind": "run.error", "detail": {"message": message}, "outcome": "unknown",
            "attributed_to": "toolchain", "evidence": {"file": "runner.py", "line": 1},
        }]
        fp, verdict = _pipeline(tmp_path, claims, events)
        assert fp["coverage"]["run_timeout"] is True
        assert verdict["verdict"] == "INCONCLUSIVE"
        assert verdict["action"] == "REVIEW"


# Known detection holes (bulk env dumps, /proc/*/environ, runtime-built names, path joins).
_HOLE_SECRET_SNIPPETS = [
    "payload = dict(os.environ)",
    "x = {k: v for k, v in os.environ.items()}",
    "json.dumps(dict(os.environ))",
    "vars = {**os.environ}",
    "e = os.environ._data",
    "from os import environ\nd = dict(environ)",
    "for k in os.environ:\n    send(k, os.environ[k])",
    "open('/proc/self/environ').read()",
    "open(f'/proc/{os.getpid()}/environ').read()",
    "open('/proc/' + str(os.getpid()) + '/environ').read()",
    "os.getenv(f'GITHUB_{t}')",
    "os.environ.get(f\"{'AWS'}_SECRET_ACCESS_KEY\")",
    "n = 'GITHUB_TOKEN'\nos.getenv(n)",
    "os.environ[''.join(['AWS_', 'SECRET_ACCESS_KEY'])]",
    "os.getenv('{}_TOKEN'.format('NPM'))",
    "os.path.join(home, '.aws', 'credentials')",
    "os.path.join(h, '.docker', 'config.json')",
    "os.path.join(h, '.kube', 'config')",
    "'/'.join(['', 'etc', 'shadow'])",
    "Path.home().joinpath('.ssh', 'id_rsa')",
]
_HOLE_BENIGN_SNIPPETS = [
    "print(len(os.environ))",
    "'HOME' in os.environ",
    "os.getenv(f'{prefix}_DEBUG')",
    "Path.home() / '.cache' / 'mytool'",
    "os.path.join(h, '.config', 'mytool', 'settings.toml')",
    "open('/proc/self/status').read()",
    "n = 'HOME'\nos.getenv(n)",
    "os.environ.setdefault('LANG', 'C')",
]


@pytest.mark.parametrize("snippet", _HOLE_SECRET_SNIPPETS)
def test_regression_detection_holes_are_secret(tmp_path, snippet):
    claims = _cli_claims(tmp_path)
    _expect_secret_contexts(tmp_path, claims, snippet)


@pytest.mark.parametrize("snippet", _HOLE_BENIGN_SNIPPETS)
def test_regression_detection_holes_benign_stay_benign(tmp_path, snippet):
    claims = _cli_claims(tmp_path)
    _expect_benign_contexts(tmp_path, claims, snippet)


@pytest.mark.parametrize("path", ["/proc/self/environ", "/proc/1/environ", "/w/home/../../proc/self/environ"])
def test_proc_environ_read_is_env_secret(path):
    from trustlens.fingerprint.normalize import classify

    cap, _ = classify({"kind": "file.read", "detail": {"path": path}})
    assert cap == ("env_secrets" if path.startswith("/proc/") else None)


def test_secret_scan_never_crashes_on_odd_code():
    from trustlens.fingerprint.normalize import snippet_has_denylisted_secret

    for text in ("", "(((", "x = '" + "a" * 30000, "def f(:\n", "\x00", "a" * 50 + "+" * 50, "f'{" * 40):
        assert snippet_has_denylisted_secret(text) in (True, False)
