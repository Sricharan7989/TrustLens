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
import tarfile
import urllib.request
import zipfile
from pathlib import Path

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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--max-kb", type=int, default=400)
    ap.add_argument("--top", type=int, default=1500, help="sample from the first TOP rows")
    ap.add_argument("--dest", default="data/clean")
    a = ap.parse_args()
    rows = json.load(get(TOP))["rows"][: a.top]
    pool = [r["project"] for r in rows if r["project"] not in MUST]
    cand = MUST + random.Random(a.seed).sample(pool, min(len(pool), a.n * 3))
    out, chosen = Path(a.dest), []
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
        chosen.append({"name": name, "version": ver, "file": f["filename"], "size": f["size"], "src": str(src)})
        print(f'{name} {ver} {f["filename"]} {f["size"] // 1024} KB')
    (out / "chosen.json").write_text(json.dumps({"seed": a.seed, "packages": chosen}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
