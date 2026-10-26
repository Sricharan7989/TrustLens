"""Dev B: rule-based claim extraction (no LLM). v1: README + pyproject/setup/metadata -> intents -> licensed capabilities."""
from __future__ import annotations

import configparser
import hashlib
import re
import tomllib
from pathlib import Path

from trustlens.contracts import load_capabilities

README_NAMES = ("README.md", "README.rst", "README.txt", "README")

DEP_INTENT_MAP = {
    "requests": "http_client",
    "httpx": "http_client",
    "urllib3": "http_client",
    "aiohttp": "http_client",
    "paramiko": "ssh_tool",
    "asyncssh": "ssh_tool",
    "psutil": "system_info",
}

CLASSIFIER_INTENT_MAP = {
    "Topic :: Internet :: WWW/HTTP": "http_client",
    "Environment :: Console": "cli_tool",
    "Topic :: System :: Systems Administration": "system_info",
}


def _walk_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts:
            yield p


def read_package_info(pkg_path: str) -> dict:
    root = Path(pkg_path).resolve()
    name, version = root.name.replace("_", "-"), "0"

    # 1. Try pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(errors="replace"))
            proj = data.get("project", {})
            name = proj.get("name", name)
            version = str(proj.get("version", version))
        except Exception:
            pass

    # 2. Try setup.py
    setup = root / "setup.py"
    if setup.exists():
        txt = setup.read_text(errors="replace")
        m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", txt)
        v = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", txt)
        if m:
            name = m.group(1)
        if v:
            version = v.group(1)

    # 3. Try PKG-INFO or METADATA
    for meta_name in ("PKG-INFO", "METADATA"):
        meta_file = root / meta_name
        if meta_file.exists():
            for line in meta_file.read_text(errors="replace").splitlines():
                if line.startswith("Name:"):
                    name = line.partition(":")[2].strip()
                elif line.startswith("Version:"):
                    version = line.partition(":")[2].strip()

    h = hashlib.sha256()
    for p in _walk_files(root):
        h.update(str(p.relative_to(root)).encode())
        h.update(p.read_bytes())
    return {"name": name, "version": version, "ecosystem": "pypi", "sha256": h.hexdigest(), "path": str(root)}


def _clean_readme(raw_text: str) -> str:
    """Strip code fences, badges, and heading tags from README text."""
    # Strip markdown code blocks
    text = re.sub(r"```[\s\S]*?```", " ", raw_text)
    text = re.sub(r"~~~[\s\S]*?~~~", " ", text)
    # Strip badges and images
    text = re.sub(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", " ", text)
    text = re.sub(r"!\[.*?\]\(.*?\)", " ", text)
    text = re.sub(r"\[.*?\]\(https?://[^\s)]+badge[^\s)]*\)", " ", text)
    # Strip headings (# Title)
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _extract_metadata(root: Path) -> dict:
    """Extract description, classifiers, entry_points, and dependencies from package metadata files."""
    summary = ""
    classifiers: list[str] = []
    entry_points: list[str] = []
    deps: list[str] = []

    # pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(errors="replace"))
            proj = data.get("project", {})
            if not summary and proj.get("description"):
                summary = proj["description"]
            classifiers.extend(proj.get("classifiers", []))
            deps.extend(proj.get("dependencies", []))
            scripts = proj.get("scripts", {})
            for k, val in scripts.items():
                entry_points.append(f"{k} = {val}")
        except Exception:
            pass

    # setup.py
    setup = root / "setup.py"
    if setup.exists():
        txt = setup.read_text(errors="replace")
        if not summary:
            m = re.search(r"description\s*=\s*['\"]([^'\"]+)['\"]", txt)
            if m:
                summary = m.group(1)
        # console_scripts
        m_scripts = re.search(r"['\"]?console_scripts['\"]?\s*[:=]\s*\[(.*?)\]", txt, re.S)
        if m_scripts:
            for s in re.findall(r"['\"]([^'\"]+)['\"]", m_scripts.group(1)):
                entry_points.append(s)
        # classifiers
        m_cls = re.search(r"['\"]?classifiers['\"]?\s*[:=]\s*\[(.*?)\]", txt, re.S)
        if m_cls:
            for c in re.findall(r"['\"]([^'\"]+)['\"]", m_cls.group(1)):
                classifiers.append(c)
        # install_requires
        m_req = re.search(r"['\"]?install_requires['\"]?\s*[:=]\s*\[(.*?)\]", txt, re.S)
        if m_req:
            for r in re.findall(r"['\"]([^'\"]+)['\"]", m_req.group(1)):
                deps.append(r)

    # setup.cfg
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        try:
            cp = configparser.ConfigParser()
            cp.read_string(setup_cfg.read_text(errors="replace"))
            if not summary and cp.has_option("metadata", "description"):
                summary = cp.get("metadata", "description")
            if cp.has_section("options.entry_points"):
                for _, val in cp.items("options.entry_points"):
                    entry_points.extend(val.splitlines())
            if cp.has_option("options", "install_requires"):
                deps.extend(cp.get("options", "install_requires").splitlines())
        except Exception:
            pass

    # METADATA / PKG-INFO
    for meta_name in ("METADATA", "PKG-INFO"):
        meta_file = root / meta_name
        if meta_file.exists():
            for line in meta_file.read_text(errors="replace").splitlines():
                if not summary and line.startswith("Summary:"):
                    summary = line.partition(":")[2].strip()
                elif line.startswith("Classifier:"):
                    classifiers.append(line.partition(":")[2].strip())
                elif line.startswith("Requires-Dist:"):
                    deps.append(line.partition(":")[2].strip())

    return {
        "summary": summary.strip(),
        "classifiers": [c.strip() for c in classifiers if c.strip()],
        "entry_points": [ep.strip() for ep in entry_points if ep.strip()],
        "dependencies": [d.strip() for d in deps if d.strip()],
    }


def _is_non_english(text: str) -> bool:
    """Detect if text is predominantly in a non-English script (e.g., CJK, Cyrillic, Arabic)."""
    alpha_chars = [c for c in text if c.isalpha()]
    if not alpha_chars:
        return False
    # Characters outside Basic Latin and Latin Extended (e.g. CJK, Cyrillic, Arabic, Devanagari)
    non_latin = [c for c in alpha_chars if ord(c) > 0x024F]
    return (len(non_latin) / len(alpha_chars)) > 0.20


def _quote(text: str, start: int) -> str:
    a = max(text.rfind("\n", 0, start), text.rfind(". ", 0, start) + 1, 0)
    b_candidates = [i for i in (text.find("\n", start), text.find(". ", start)) if i != -1]
    b = min(b_candidates) if b_candidates else len(text)
    return text[a:b].strip(" #\n")[:200]


def extract_claims(pkg_path: str) -> dict:
    root = Path(pkg_path).resolve()
    voc = load_capabilities()["intents"]
    intents: list[dict] = []
    claims: list[dict] = []
    seen_intents: set[str] = set()

    meta = _extract_metadata(root)
    declared_entry_points = meta["entry_points"]

    # 1. Inspect README
    readme_text = ""
    for n in README_NAMES:
        p = root / n
        if p.exists():
            readme_text = _clean_readme(p.read_text(errors="replace")[:4000])
            break

    # If README exists, is meaningful (>= 20 chars), and not non-English script, extract intents
    is_non_eng = _is_non_english(readme_text)
    readme_valid = len(readme_text) >= 20 and not is_non_eng
    if readme_valid:
        for intent, spec in voc.items():
            for kw in spec["keywords"]:
                m = re.search(r"(?<![a-z])" + re.escape(kw) + r"s?(?![a-z])", readme_text, re.I)
                if m and intent not in seen_intents:
                    seen_intents.add(intent)
                    q = _quote(readme_text, m.start())
                    intents.append({"intent": intent, "confidence": 0.7, "quote": q, "source": "readme"})
                    for cap in spec.get("allow", []):
                        claims.append({
                            "capability": cap,
                            "basis": "intent_prior",
                            "quote": q,
                            "source": "readme",
                            "phases_allowed": spec.get("phases_allowed", ["import", "call", "cli"]),
                        })
                    break

    # 2. Inspect metadata summary / description (ignoring non-English summaries)
    if meta["summary"] and not _is_non_english(meta["summary"]):
        for intent, spec in voc.items():
            if intent in seen_intents:
                continue
            for kw in spec["keywords"]:
                m = re.search(r"(?<![a-z])" + re.escape(kw) + r"s?(?![a-z])", meta["summary"], re.I)
                if m and intent not in seen_intents:
                    seen_intents.add(intent)
                    q = meta["summary"][:200]
                    intents.append({"intent": intent, "confidence": 0.6, "quote": q, "source": "summary"})
                    for cap in spec.get("allow", []):
                        claims.append({
                            "capability": cap,
                            "basis": "intent_prior",
                            "quote": q,
                            "source": "summary",
                            "phases_allowed": spec.get("phases_allowed", ["import", "call", "cli"]),
                        })
                    break

    # 3. Classifiers
    for cls_name in meta["classifiers"]:
        for prefix, intent in CLASSIFIER_INTENT_MAP.items():
            if cls_name.startswith(prefix) and intent not in seen_intents:
                seen_intents.add(intent)
                spec = voc.get(intent, {})
                intents.append({"intent": intent, "confidence": 0.8, "quote": cls_name, "source": "classifier"})
                for cap in spec.get("allow", []):
                    claims.append({
                        "capability": cap,
                        "basis": "intent_prior",
                        "quote": cls_name,
                        "source": "classifier",
                        "phases_allowed": spec.get("phases_allowed", ["import", "call", "cli"]),
                    })

    # 4. Entry points -> cli_tool
    if declared_entry_points and "cli_tool" not in seen_intents:
        seen_intents.add("cli_tool")
        spec = voc.get("cli_tool", {})
        ep_quote = f"console_scripts: {', '.join(declared_entry_points)}"[:200]
        intents.append({"intent": "cli_tool", "confidence": 0.8, "quote": ep_quote, "source": "entry_points"})
        for cap in spec.get("allow", []):
            claims.append({
                "capability": cap,
                "basis": "intent_prior",
                "quote": ep_quote,
                "source": "entry_points",
                "phases_allowed": spec.get("phases_allowed", ["call", "cli"]),
            })

    # 5. Dependencies: only license when NOT contradicted by a pure-computation claim (string_util)
    is_pure_computation = "string_util" in seen_intents
    if not is_pure_computation:
        for dep in meta["dependencies"]:
            dep_clean = re.split(r"[><=~;!\[]", dep)[0].strip().lower()
            if dep_clean in DEP_INTENT_MAP:
                intent = DEP_INTENT_MAP[dep_clean]
                if intent not in seen_intents:
                    seen_intents.add(intent)
                    spec = voc.get(intent, {})
                    q = f"Dependency: {dep}"
                    intents.append({"intent": intent, "confidence": 0.5, "quote": q, "source": "keywords"})
                    for cap in spec.get("allow", []):
                        claims.append({
                            "capability": cap,
                            "basis": "intent_prior",
                            "quote": q,
                            "source": "deps",
                            "phases_allowed": spec.get("phases_allowed", ["import", "call", "cli"]),
                        })

    # Item 6: if cleaned README < 20 characters, set unknown_intent true, claims [] and intents [] even when description/classifiers/entry points matched.
    if len(readme_text) < 20:
        unknown_intent = True
        claims = []
        intents = []
    else:
        # Item 10: Non-English README (>= 20 chars) skipped README keywords, but keeps claims from
        # classifiers, entry points, and English summary. unknown_intent only when no intent remains.
        unknown_intent = not intents
        if unknown_intent:
            claims = []

    return {
        "schema_version": "1.0",
        "package": read_package_info(str(root)),
        "intents": intents,
        "claims": claims,
        "unknown_intent": unknown_intent,
        "declared_entry_points": declared_entry_points,
    }

