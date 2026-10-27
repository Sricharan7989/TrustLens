"""Dev C: pick clean controls from the top-PyPI list and download their sdists (or wheels) WITHOUT running pip or any package code.

  python bench/tools/pick_clean.py --n 30 --seed 1337 --max-kb 400            # needs network, writes data/clean/<pkg>/<ver>/src/
Always includes the noisy-benign MUST list. Extraction uses tarfile/zipfile 'data' filter semantics (no absolute paths / links).
Match the clean set's size distribution to the malicious set (Datadog samples are mostly < 50 KB): use --max-kb and check bench/tools/size_report.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from trustlens.contracts import validate  # noqa: E402

TOP = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
MUST = ["requests", "paramiko", "psutil", "GitPython", "docker", "six", "idna", "colorama", "python-slugify"]


def get(url: str):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "trustlens-bench"}), timeout=60)


def pick_file(files: list[dict], max_kb: int):
    for kind in ("sdist", "bdist_wheel"):
        for f in files:
            if f["packagetype"] == kind and not f.get("yanked") and f["size"] <= max_kb * 1024 and (kind == "sdist" or f["filename"].endswith("py3-none-any.whl")):
                return f
    return None


def resolve_pkg_root(src: Path, name: str, summary: str) -> Path:
    """Locate package root inside sdist extraction folder and ensure README.md exists."""
    pkg_root = src
    children = [p for p in src.iterdir() if p.is_dir() and not p.name.endswith(".dist-info")]
    if len(children) == 1:
        inner = children[0]
        if (inner / "setup.py").exists() or (inner / "pyproject.toml").exists() or any((inner / r).exists() for r in ("README.md", "README.rst", "README.txt")):
            pkg_root = inner

    readme = pkg_root / "README.md"
    if not readme.exists():
        for r in ("README.rst", "README.txt", "README"):
            alt = pkg_root / r
            if alt.exists():
                try:
                    readme.write_text(alt.read_text(errors="replace"), encoding="utf-8")
                    break
                except Exception:
                    pass
        else:
            readme.write_text(f"# {name}\n\n{summary}\n", encoding="utf-8")
    return pkg_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--max-kb", type=int, default=400)
    ap.add_argument("--top", type=int, default=1500, help="sample from the first TOP rows")
    ap.add_argument("--dest", default="data/clean")
    a = ap.parse_args()

    out = ROOT / a.dest if not Path(a.dest).is_absolute() else Path(a.dest)
    out.mkdir(parents=True, exist_ok=True)
    top_file = out / "top-pypi.json"
    if top_file.exists():
        rows = json.loads(top_file.read_text(encoding="utf-8"))["rows"][: a.top]
    else:
        resp_data = get(TOP).read()
        top_file.write_bytes(resp_data)
        rows = json.loads(resp_data.decode("utf-8"))["rows"][: a.top]

    pool = [r["project"] for r in rows if r["project"] not in MUST]
    cand = MUST + random.Random(a.seed).sample(pool, min(len(pool), a.n * 3))
    chosen = []

    for name in cand:
        if len(chosen) >= a.n:
            break
        try:
            info = json.load(get(f"https://pypi.org/pypi/{name}/json"))
        except Exception:  # noqa: BLE001
            continue
        f = pick_file(info["urls"], a.max_kb)
        if not f:
            continue
        ver, dst = info["info"]["version"], out / name / info["info"]["version"]
        src = dst / "src"
        if not src.exists():
            dst.mkdir(parents=True, exist_ok=True)
            blob = get(f["url"]).read()
            if hashlib.sha256(blob).hexdigest() != f["digests"]["sha256"]:
                continue
            arc = dst / f["filename"]
            arc.write_bytes(blob)
            if arc.suffix == ".whl" or arc.suffix == ".zip":
                zipfile.ZipFile(arc).extractall(src)  # zipfile strips absolute paths and '..'
            else:
                with tarfile.open(arc) as t:
                    t.extractall(src, filter="data")

        summary = info["info"].get("summary") or f"Top-PyPI package {name}"
        pkg_root = resolve_pkg_root(src, name, summary)
        chosen.append({
            "name": name,
            "version": ver,
            "file": f["filename"],
            "size": f["size"],
            "sha256": f["digests"]["sha256"],
            "src": str(pkg_root),
            "claim": summary,
        })
        print(f'{name} {ver} {f["filename"]} {f["size"] // 1024} KB')

    # Save chosen.json
    (out / "chosen.json").write_text(json.dumps({"seed": a.seed, "packages": chosen}, indent=1))

    # Generate bench/labels_external.yaml
    labels_ext = {
        "version": 1,
        "packages": [
            {
                "id": c["name"].replace(".", "-").replace("_", "-").lower(),
                "path": str(Path(c["src"]).relative_to(ROOT)).replace("\\", "/"),
                "label": "clean",
                "category": "top_pypi",
                "claim": c.get("claim") or c["name"],
                "expected_verdict": "BENIGN-CONSISTENT",
                "notes": f"Top-PyPI clean control {c['name']} {c['version']} (sha256: {c['sha256'][:16]}...)",
            }
            for c in chosen
        ],
    }
    validate("bench_labels", labels_ext)
    labels_path = ROOT / "bench" / "labels_external.yaml"
    labels_path.write_text(yaml.safe_dump(labels_ext, sort_keys=False))
    print(f"Generated {labels_path} with {len(chosen)} packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
