"""Dev C: reproducible Datadog PyPI sample. NEVER downloads the whole repo; blobless sparse checkout of the sampled package dirs only.

  python bench/tools/sample_datadog.py --n 150 --seed 1337 --dry-run     # prints the sample, downloads only manifest.json (small)
  python bench/tools/sample_datadog.py --n 150 --seed 1337               # + blobless sparse clone into data/datadog/ (zips stay zipped)
Zip password is 'infected'. EXTRACT ONLY INSIDE THE SANDBOX (scripts/extract_in_sandbox.sh). Never on the host.
Manifest: name -> null (every version malicious) | [bad versions]. We sample only the null ones (kind malicious_intent).
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import urllib.request
from pathlib import Path

RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
REPO = "https://github.com/DataDog/malicious-software-packages-dataset.git"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--dest", default="data/datadog")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    manifest = json.load(urllib.request.urlopen(RAW, timeout=60))
    names = sorted(k for k, v in manifest.items() if v is None)
    sample = sorted(random.Random(a.seed).sample(names, min(a.n, len(names))))
    (dest / "sample.json").write_text(json.dumps({"seed": a.seed, "n": len(sample), "packages": sample}, indent=1))
    print(f"{len(names)} all-versions-malicious packages in manifest; sampled {len(sample)} with seed {a.seed}: {', '.join(sample[:8])} ...")
    if a.dry_run:
        return 0
    repo = dest / "repo"
    if not repo.exists():
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1", REPO, str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "sparse-checkout", "init", "--cone"], check=True)
    subprocess.run(["git", "-C", str(repo), "sparse-checkout", "set"] + [f"samples/pypi/malicious_intent/{p}" for p in sample], check=True)
    subprocess.run(["git", "-C", str(repo), "checkout", "main"], check=True)
    print(f"zips are under {repo}/samples/pypi/malicious_intent/ (password 'infected'); extract inside the sandbox only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
