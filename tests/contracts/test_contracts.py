"""Lead-owned. Contracts are the integration glue: if this fails, someone broke a frozen interface."""
import json

import jsonschema
import pytest
import yaml

from trustlens.contracts import EXAMPLES, KINDS, ROOT, iter_jsonl, load_capabilities, load_schema, validate

FIXTURES = ["evil_slug", "delayed_slug", "clean_slug", "rest_wrapper", "_synthetic_pth_startup"]


@pytest.mark.parametrize("kind", KINDS)
def test_schema_is_valid_json_schema(kind):
    jsonschema.Draft202012Validator.check_schema(load_schema(kind))


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_raw_events_and_meta_validate(name):
    d = EXAMPLES / name
    evs = list(iter_jsonl(d / "raw_events.jsonl"))
    for e in evs:
        validate("raw_event", e)
    validate("run_meta", json.loads((d / "run_meta.json").read_text()))


@pytest.mark.parametrize("name", ["evil_slug", "delayed_slug", "clean_slug", "rest_wrapper"])
def test_generated_examples_validate(name):
    for kind in ("claims", "fingerprint", "verdict"):
        validate(kind, json.loads((EXAMPLES / name / f"{kind}.json").read_text()))


def test_capabilities_vocabulary_is_consistent():
    cap = load_capabilities()
    names = set(cap["capabilities"])
    for intent, spec in cap["intents"].items():
        assert set(spec["allow"]) <= names, intent
        assert set(spec.get("phases_allowed", [])) <= set(cap["phases"]), intent


def test_labels_validate_and_paths_exist():
    labels = yaml.safe_load((ROOT / "bench" / "labels.yaml").read_text())
    validate("bench_labels", labels)
    for p in labels["packages"]:
        assert (ROOT / p["path"]).exists(), p["path"]


def test_validate_rejects_garbage():
    with pytest.raises(Exception):  # noqa: B017
        validate("raw_event", {"kind": "nope"})
