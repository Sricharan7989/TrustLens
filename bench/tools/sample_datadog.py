"""Dev C: reproducible Datadog PyPI sample. NEVER downloads the whole repo; blobless sparse checkout of the sampled package dirs only.

  python bench/tools/sample_datadog.py --n 150 --seed 1337 --dry-run     # prints the sample, downloads only manifest.json (small)
  python bench/tools/sample_datadog.py --n 150 --seed 1337               # + blobless sparse clone into data/datadog/ and safe extract
Zip password is 'infected'. EXTRACT ONLY INSIDE THE SANDBOX (scripts/extract_in_sandbox.sh) or safe data extraction fallback.
Manifest: name -> null (every version malicious) | [bad versions]. We sample only the null ones (kind malicious_intent).
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from trustlens.contracts import validate  # noqa: E402

RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
REPO = "https://github.com/DataDog/malicious-software-packages-dataset.git"


def safe_extract_zip(zip_path: Path, target_dir: Path) -> bool:
    """Extract password-protected zip without executing any code. Uses extract_in_sandbox.sh if bwrap is available."""
    target_dir.mkdir(parents=True, exist_ok=True)
    extract_sh = ROOT / "scripts" / "extract_in_sandbox.sh"
    if shutil.which("bwrap") and extract_sh.exists():
        try:
            res = subprocess.run(["bash", str(extract_sh), str(zip_path), str(target_dir)], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                return True
        except Exception:
            pass

    try:
        with zipfile.ZipFile(zip_path) as z:
            z.setpassword(b"infected")
            for member in z.infolist():
                clean_name = member.filename.replace("\\", "/")
                if clean_name.startswith("/") or ".." in clean_name.split("/"):
                    continue
                z.extract(member, target_dir)
        return True
    except Exception as e:
        print(f"Warning: failed extracting {zip_path.name}: {e}", file=sys.stderr)
        return False


def find_pkg_root(target: Path, name: str) -> Path:
    """Locate package root and ensure README.md exists for claim analysis."""
    pkg_root = target
    for sub in sorted(target.rglob("*")):
        if sub.is_dir() and ((sub / "setup.py").exists() or (sub / "pyproject.toml").exists() or (sub / "PKG-INFO").exists()):
            pkg_root = sub
            break

    readme = pkg_root / "README.md"
    if not readme.exists():
        for alt_name in ("README.rst", "README.txt", "README"):
            alt = pkg_root / alt_name
            if alt.exists():
                try:
                    readme.write_text(alt.read_text(errors="replace"), encoding="utf-8")
                    break
                except Exception:
                    pass
        else:
            readme.write_text(f"# {name}\n\nDatadog malicious sample {name}.\n", encoding="utf-8")
    return pkg_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--dest", default="data/datadog")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

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

    # Extract zips into data/datadog/extracted/<pkg_name>
    extracted_base = dest / "extracted"
    extracted_base.mkdir(parents=True, exist_ok=True)
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

        if not target_dir.exists():
            for z in zips:
                safe_extract_zip(z, target_dir)

        pkg_root = find_pkg_root(target_dir, pkg_name)
        extracted_packages.append({
            "id": pkg_name.replace(".", "-").replace("_", "-").lower(),
            "name": pkg_name,
            "path": str(pkg_root.relative_to(ROOT)).replace("\\", "/"),
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
                "claim": f"Datadog malicious sample {p['name']}",
                "expected_verdict": "MALICIOUS-EVIDENT",
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
