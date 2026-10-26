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
    assert v["verdict"] == "MALICIOUS-EVIDENT" and any(f["rule"] == "startup_hook" for f in v["findings"])


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
