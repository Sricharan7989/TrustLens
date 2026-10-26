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
