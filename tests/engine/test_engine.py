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
        assert f"During {f['phases'][0]}" in exp
        assert "The README says:" in exp or "claim" in exp
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
    # Benign shim should have signal_class info, not strong decoded_exec
    assert "decoded_exec" not in v["independent_signals"]
    assert v["verdict"] != "MALICIOUS-EVIDENT"


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
    assert any(f["rule"] == "static_shady-links" for f in v["findings"])
    # Weak static signal cannot solely make the verdict MALICIOUS-EVIDENT
    assert v["verdict"] != "MALICIOUS-EVIDENT"
    assert "static_signal" not in v["independent_signals"]


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
    # Case 1: Chinese README
    p_zh = tmp_path / "pkg_zh"
    p_zh.mkdir()
    (p_zh / "README.md").write_text("这是一个用于高效处理字符串与文本清洗的工具包。提供全面的分词和过滤能力。")
    (p_zh / "setup.py").write_text("from setuptools import setup\nsetup(name='pkg_zh', version='1.0')\n")
    c_zh = extract_claims(str(p_zh))
    validate("claims", c_zh)
    assert c_zh["unknown_intent"] is True
    assert c_zh["claims"] == []

    # Case 2: Russian README
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
        assert isinstance(v["score"], (int, float))
