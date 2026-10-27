"""Shared contract helpers. OWNER: Lead (shared file). Do not edit without a contract-change PR.

validate(kind, obj) raises ContractError when `obj` does not match schemas/<kind>.schema.json.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
# A repo checkout has schemas/ next to the package. An installed package (pip) carries copies of the
# schemas and the calibrated noise whitelist as package data (trustlens/_schemas, trustlens/_calibration).
IN_REPO = (ROOT / "schemas" / "capabilities.yaml").is_file()
_PKG = Path(__file__).resolve().parent
SCHEMAS = ROOT / "schemas" if IN_REPO else _PKG / "_schemas"
EXAMPLES = SCHEMAS / "examples"
CALIBRATION_WHITELIST = (ROOT / "bench" / "calibration" if IN_REPO else _PKG / "_calibration") / "noise_whitelist.yaml"
# Where reports go by default: the repo in a checkout, the current folder when installed (never site-packages).
OUTPUT_ROOT = ROOT if IN_REPO else Path.cwd()
KINDS = ("raw_event", "run_meta", "fingerprint", "claims", "verdict", "bench_labels", "eval_results")


class ContractError(ValueError):
    pass


@cache
def load_schema(kind: str) -> dict:
    if kind not in KINDS:
        raise ContractError(f"unknown contract kind {kind!r}; expected one of {KINDS}")
    return json.loads((SCHEMAS / f"{kind}.schema.json").read_text())


@lru_cache(maxsize=1)
def load_capabilities() -> dict:
    return yaml.safe_load((SCHEMAS / "capabilities.yaml").read_text())


def validate(kind: str, obj: Any) -> None:
    import jsonschema

    try:
        jsonschema.validate(obj, load_schema(kind))
    except jsonschema.ValidationError as e:  # pragma: no cover - message formatting
        path = "/".join(str(p) for p in e.absolute_path)
        raise ContractError(f"{kind} invalid at '{path}': {e.message}") from e


def iter_jsonl(path: str | Path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
