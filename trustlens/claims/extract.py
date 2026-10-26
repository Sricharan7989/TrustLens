"""Dev B: rule-based claim extraction (no LLM). STUB-LEVEL v0: keyword -> intent -> licensed capabilities.

TODO(Dev B): explicit-claim patterns, classifiers/keywords/entry_points sources, pyproject/PKG-INFO/METADATA parsing,
sdist/wheel/zip inputs, tests on all bench packages. Keep the output conforming to schemas/claims.schema.json.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from trustlens.contracts import load_capabilities

README_NAMES = ("README.md", "README.rst", "README.txt", "README")


def _walk_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts:
            yield p


def read_package_info(pkg_path: str) -> dict:
    root = Path(pkg_path).resolve()
    name, version = root.name.replace("_", "-"), "0"
    setup = root / "setup.py"
    if setup.exists():
        txt = setup.read_text(errors="replace")
        m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", txt)
        v = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", txt)
        name, version = (m.group(1) if m else name), (v.group(1) if v else version)
    h = hashlib.sha256()
    for p in _walk_files(root):
        h.update(str(p.relative_to(root)).encode())
        h.update(p.read_bytes())
    return {"name": name, "version": version, "ecosystem": "pypi", "sha256": h.hexdigest(), "path": str(root)}


def _texts(root: Path) -> list[tuple[str, str]]:
    out = []
    for n in README_NAMES:
        if (root / n).exists():
            body = "\n".join(ln for ln in (root / n).read_text(errors="replace")[:4000].splitlines() if not ln.lstrip().startswith("#"))
            out.append(("readme", body))  # headings dropped: they carry the package name, not a claim
            break
    setup = root / "setup.py"
    if setup.exists():
        m = re.search(r"description\s*=\s*['\"]([^'\"]+)['\"]", setup.read_text(errors="replace"))
        if m:
            out.append(("summary", m.group(1)))
    return out


def _quote(text: str, start: int) -> str:
    a = max(text.rfind("\n", 0, start), text.rfind(". ", 0, start) + 1, 0)
    b_candidates = [i for i in (text.find("\n", start), text.find(". ", start)) if i != -1]
    b = min(b_candidates) if b_candidates else len(text)
    return text[a:b].strip(" #\n")[:200]


def extract_claims(pkg_path: str) -> dict:
    root = Path(pkg_path).resolve()
    voc = load_capabilities()["intents"]
    intents, claims, seen = [], [], set()
    for source, text in _texts(root):
        for intent, spec in voc.items():
            for kw in spec["keywords"]:
                m = re.search(r"(?<![a-z])" + re.escape(kw) + r"s?(?![a-z])", text, re.I)
                if m and intent not in seen:
                    seen.add(intent)
                    q = _quote(text, m.start())
                    intents.append({"intent": intent, "confidence": 0.6, "quote": q, "source": source})
                    for cap in spec.get("allow", []):
                        claims.append({"capability": cap, "basis": "intent_prior", "quote": q, "source": source,
                                       "phases_allowed": spec.get("phases_allowed", ["import", "call", "cli"])})
                    break
    return {"schema_version": "1.0", "package": read_package_info(str(root)), "intents": intents, "claims": claims,
            "unknown_intent": not intents, "declared_entry_points": []}
