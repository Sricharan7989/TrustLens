"""Site-packages diff after an offline install: .pth lines, sitecustomize, entry points, new files."""
from __future__ import annotations

import time
from pathlib import Path


def _event(kind: str, detail: dict, *, profile: str, evidence: dict, line: int | None = None) -> dict:
    ev = dict(evidence)
    if line is not None:
        ev["line"] = line
    return {
        "seq": 0,
        "t": time.time(),
        "phase": "install",
        "trigger": "install",
        "profile": profile,
        "variant": "default",
        "kind": kind,
        "detail": detail,
        "outcome": "succeeded",
        "attributed_to": "pkg",
        "canary_match": [],
        "evidence": ev,
    }


def package_names(installed: Path) -> set[str]:
    names: set[str] = set()
    if not installed.is_dir():
        return names
    for child in installed.iterdir():
        if child.is_dir() and (child / "__init__.py").is_file():
            names.add(child.name)
        elif child.is_file() and child.suffix == ".py":
            names.add(child.stem)
    for top in installed.glob("*.dist-info/top_level.txt"):
        for line in top.read_text(encoding="utf-8", errors="replace").splitlines():
            text = line.strip()
            if text:
                names.add(text.split("/")[0])
    return names


def console_scripts(text: str) -> list[tuple[str, str]]:
    """Parse console_scripts entries as (name, module:function)."""
    scripts: list[tuple[str, str]] = []
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_section = line == "[console_scripts]"
            continue
        if in_section and "=" in line and not line.startswith("#"):
            name, target = (part.strip() for part in line.split("=", 1))
            if name and ":" in target:
                scripts.append((name, target))
    return scripts


def cmdclass_hooks(setup_text: str) -> list[dict]:
    if "cmdclass" not in setup_text:
        return []
    return [{"file": "setup.py", "cmd": "cmdclass"}]


def diff_installed(installed: Path, *, profile: str, setup_text: str = "") -> tuple[list[dict], list[str], list[tuple[str, str]]]:
    """Return (events, files_added, console entry points)."""
    events: list[dict] = []
    files: list[str] = []
    scripts: list[tuple[str, str]] = []
    if not installed.is_dir():
        for hook in cmdclass_hooks(setup_text):
            events.append(_event("install.hook", hook, profile=profile, evidence={"layer": "fs_diff", "file": "setup.py", "line": None}))
        return events, files, scripts
    packages = package_names(installed)
    for path in sorted(p for p in installed.rglob("*") if p.is_file()):
        rel = path.relative_to(installed).as_posix()
        files.append(rel)
        evidence = {"layer": "fs_diff", "file": rel, "line": None}
        if path.name.endswith(".pth") and path.parent == installed:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for number, line in enumerate(lines, start=1):
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                events.append(_event("startup.pth", {"file": rel, "line_text": text}, profile=profile, evidence=evidence, line=number))
        if path.name in {"sitecustomize.py", "usercustomize.py"} and path.parent == installed:
            body = path.read_text(encoding="utf-8", errors="replace").splitlines()
            line_text = next((ln.strip() for ln in body if ln.strip()), "")
            events.append(
                _event("startup.sitecustomize", {"file": rel, "line_text": line_text[:300]}, profile=profile, evidence=evidence, line=1)
            )
        if rel.endswith(".dist-info/entry_points.txt") or rel.endswith(".egg-info/entry_points.txt"):
            for name, target in console_scripts(path.read_text(encoding="utf-8", errors="replace")):
                scripts.append((name, target))
                events.append(
                    _event("install.hook", {"file": rel, "cmd": f"{name}={target}"}, profile=profile, evidence=evidence)
                )
        top = rel.split("/", 1)[0]
        meta = top.endswith(".dist-info") or top.endswith(".egg-info") or top in {"bin", "__pycache__"}
        outside = top not in packages and not meta
        if outside and "/__pycache__/" not in rel:
            events.append(_event("file.new", {"path": rel, "mode": "new"}, profile=profile, evidence=evidence))
    for hook in cmdclass_hooks(setup_text):
        events.append(_event("install.hook", hook, profile=profile, evidence={"layer": "fs_diff", "file": "setup.py", "line": None}))
    # Stable order for tests: kind, path/file, line.
    events.sort(key=lambda e: (e["kind"], json_key(e), e["evidence"].get("line") or 0))
    return events, files, scripts


def json_key(event: dict) -> str:
    detail = event.get("detail") or {}
    return str(detail.get("file") or detail.get("path") or detail.get("cmd") or "")
