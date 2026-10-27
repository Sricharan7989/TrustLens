"""Dev C: reproducible Datadog PyPI sample. NEVER downloads the whole repo; blobless sparse checkout of the sampled package dirs only.

  python bench/tools/sample_datadog.py --n 150 --seed 1337 --dry-run     # prints the sample, downloads only manifest.json (small)
  python bench/tools/sample_datadog.py --n 150 --seed 1337               # + blobless sparse clone into data/datadog/ and safe extract
Zip password is 'infected'. EXTRACT ONLY INSIDE THE SANDBOX (scripts/extract_in_sandbox.sh).
Manifest: name -> null (every version malicious) | [bad versions]. We sample only the null ones (kind malicious_intent).
"""
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from trustlens.contracts import validate  # noqa: E402

RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
REPO = "https://github.com/DataDog/malicious-software-packages-dataset.git"


_HTML_TAG = re.compile(r"<[^>]*>")


def safe_extract_zip(zip_path: Path, target_dir: Path) -> bool:
    """Extract a password-protected zip inside the sandbox.

    Does not create ``target_dir``. Returns False when bwrap or the script is
    missing or the sandbox exits non-zero.
    """
    extract_sh = ROOT / "scripts" / "extract_in_sandbox.sh"
    if not shutil.which("bwrap") or not extract_sh.is_file():
        return False
    res = subprocess.run(["bash", str(extract_sh), str(zip_path), str(target_dir)], capture_output=True, text=True, check=False)
    return res.returncode == 0


def find_pkg_root(target: Path, name: str) -> Path:
    """Locate package root without modifying extracted tree."""
    for sub in sorted(target.rglob("*")):
        if sub.is_dir() and ((sub / "setup.py").exists() or (sub / "pyproject.toml").exists() or (sub / "PKG-INFO").exists()):
            return sub
    return target


def descriptive_claim_line(line: str) -> str | None:
    """Return visible claim text, skipping blanks, rules, and HTML-only lines."""
    raw = line.strip()
    if not raw or raw.startswith(("==", "--", "<!--")):
        return None
    visible = _HTML_TAG.sub("", raw).replace("&nbsp;", " ").strip().lstrip("#").strip()
    if not visible or visible.startswith(("==", "--")):
        return None
    if raw.startswith("<") and visible == raw:
        return None
    return visible[:120]


def get_readme_summary(pkg_root: Path) -> str:
    """Read first descriptive README line, otherwise 'uninspected Datadog sample'."""
    for alt_name in ("README.md", "README.rst", "README.txt", "README"):
        alt = pkg_root / alt_name
        if alt.exists():
            try:
                for line in alt.read_text(errors="replace").splitlines():
                    claim = descriptive_claim_line(line)
                    if claim:
                        return claim
            except Exception:
                pass
    return "uninspected Datadog sample"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--dest", default="data/datadog")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    dest = ROOT / a.dest if not Path(a.dest).is_absolute() else Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    manifest = json.load(urllib.request.urlopen(RAW, timeout=60))
    names = sorted(k for k, v in manifest.items() if v is None)
    sample = sorted(random.Random(a.seed).sample(names, min(a.n, len(names))))

    (dest / "sample.json").write_text(json.dumps({"seed": a.seed, "n": len(sample), "packages": sample}, indent=1))

    # Save manifest list to bench/datadog_sample.txt (acceptance criteria: committed)
    manifest_txt = ROOT / "bench" / "datadog_sample.txt"
    manifest_txt.write_text("\n".join(sample) + "\n", encoding="utf-8")
    print(f"{len(names)} all-versions-malicious packages in manifest; sampled {len(sample)} with seed {a.seed}: {', '.join(sample[:8])} ...")
    print(f"Committed manifest written to {manifest_txt}")

    if a.dry_run:
        return 0

    repo = dest / "repo"
    if not repo.exists() or not (repo / ".git").exists():
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1", REPO, str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "core.protectNTFS", "false"], check=True)
    subprocess.run(["git", "-C", str(repo), "sparse-checkout", "init", "--no-cone"], check=True)

    sparse_patterns = [f"/samples/pypi/malicious_intent/{p}/*" for p in sample]
    (repo / ".git" / "info" / "sparse-checkout").write_text("\n".join(sparse_patterns) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "checkout", "main"], check=True)

    # Extract zips into data/datadog/extracted/<pkg_name>. Dest is created only after a successful sandbox extract.
    extracted_base = dest / "extracted"
    extracted_packages = []

    samples_dir = repo / "samples" / "pypi" / "malicious_intent"
    for pkg_name in sample:
        pkg_dir = samples_dir / pkg_name
        if not pkg_dir.exists():
            continue
        zips = sorted(pkg_dir.rglob("*.zip"))
        if not zips:
            continue
        target_dir = extracted_base / pkg_name
        extracted = False
        for z in zips:
            if safe_extract_zip(z, target_dir):
                extracted = True
                break
        if not extracted:
            continue

        pkg_root = find_pkg_root(target_dir, pkg_name)
        claim_summary = get_readme_summary(pkg_root)
        extracted_packages.append({
            "id": pkg_name.replace(".", "-").replace("_", "-").lower(),
            "name": pkg_name,
            "path": str(pkg_root.relative_to(ROOT)).replace("\\", "/"),
            "claim": claim_summary,
            "zips": [z.name for z in zips],
        })

    print(f"Extracted {len(extracted_packages)} packages under {extracted_base}")

    # Generate bench/labels_datadog.yaml
    labels_datadog = {
        "version": 1,
        "packages": [
            {
                "id": p["id"],
                "path": p["path"],
                "label": "malicious",
                "category": "datadog",
                "claim": p["claim"],
                "expected_verdict": None,
                "notes": f"Datadog PyPI malicious package ({', '.join(p['zips'])})",
            }
            for p in extracted_packages
        ],
    }
    validate("bench_labels", labels_datadog)
    labels_path = ROOT / "bench" / "labels_datadog.yaml"
    labels_path.write_text(yaml.safe_dump(labels_datadog, sort_keys=False), encoding="utf-8")
    print(f"Generated {labels_path} with {len(extracted_packages)} packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
