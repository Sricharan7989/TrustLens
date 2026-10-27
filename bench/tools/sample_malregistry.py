"""Dev C: Reproducible sampling and safe extraction helper for pypi_malregistry.

CRITICAL LICENSING & SAFETY REMINDERS:
1. pypi_malregistry has NO LICENSE: keep local under data/malregistry/.
2. NEVER commit sample files to git; never redistribute.
3. NEVER execute samples on the host; extract only in isolated sandbox.
4. Blobless sparse checkout only: never download the whole repository.

Usage:
    python bench/tools/sample_malregistry.py --list                        # list available packages
    python bench/tools/sample_malregistry.py --n 5 --seed 1337 --dry-run  # print sample plan without checkout
    python bench/tools/sample_malregistry.py --n 5 --seed 1337            # checkout, safe extract, and generate labels
"""
from __future__ import annotations

import argparse
import random
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustlens.contracts import validate  # noqa: E402

MR_DIR = ROOT / "data" / "malregistry" / "mr"
EXTRACTED_DIR = ROOT / "data" / "malregistry" / "extracted"
REPO_URL = "https://github.com/lxyeternal/pypi_malregistry.git"


def sample_packages(pkg_list: list[str], n: int, seed: int) -> list[str]:
    """Deterministically sample n packages using given seed."""
    rng = random.Random(seed)
    return sorted(rng.sample(pkg_list, min(n, len(pkg_list))))


def ensure_mr_clone() -> None:
    MR_DIR.parent.mkdir(parents=True, exist_ok=True)
    if not (MR_DIR / ".git").exists():
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1", REPO_URL, str(MR_DIR)],
            check=True,
            capture_output=True,
            text=True,
        )
    # Ensure Windows NTFS compatibility for directories with trailing spaces
    subprocess.run(["git", "-C", str(MR_DIR), "config", "core.protectNTFS", "false"], check=False)


def list_available_packages() -> list[str]:
    ensure_mr_clone()
    proc = subprocess.run(
        ["git", "-C", str(MR_DIR), "ls-tree", "-d", "--name-only", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    names = [line.strip() for line in proc.stdout.splitlines() if line.strip() and not line.strip().startswith(".")]
    # Filter out Windows-problematic names (trailing spaces)
    return [n for n in names if not n.endswith(" ")]


def safe_extract_archive(archive_path: Path, target_dir: Path) -> bool:
    """Extract archive inside bwrap sandbox using scripts/extract_in_sandbox.sh. Never extract on host."""
    target_dir.mkdir(parents=True, exist_ok=True)
    extract_sh = ROOT / "scripts" / "extract_in_sandbox.sh"

    if not shutil.which("bwrap") or not extract_sh.exists():
        return False

    try:
        res = subprocess.run(
            ["bash", str(extract_sh), str(archive_path), str(target_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False



def find_pkg_root(target: Path, name: str) -> Path:
    """Locate package root and ensure README.md exists for claim inspection."""
    pkg_root = target
    for sub in sorted(target.rglob("*")):
        if sub.is_dir() and any((sub / f).exists() for f in ("setup.py", "pyproject.toml", "PKG-INFO")):
            pkg_root = sub
            break

    readme = pkg_root / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# {name}\n\nMalicious package sample from pypi_malregistry (backup dataset).\n",
            encoding="utf-8",
        )
    return pkg_root


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Reproducible sampler for pypi_malregistry (local backup only)")
    ap.add_argument("--list", action="store_true", help="List available packages in malregistry")
    ap.add_argument("--n", type=int, default=5, help="Number of packages to sample (default: 5)")
    ap.add_argument("--seed", type=int, default=1337, help="Random seed for sampling (default: 1337)")
    ap.add_argument("--dry-run", action="store_true", help="Print sample plan without checkout")
    ap.add_argument("--packages", nargs="*", help="Specific package names to fetch")
    ap.add_argument("--out-labels", default=str(ROOT / "bench" / "labels_malregistry.yaml"), help="Output labels YAML path")
    a = ap.parse_args(argv)

    if a.dry_run:
        if (MR_DIR / ".git").exists():
            pkgs = list_available_packages()
        else:
            pkgs = [f"mal_{i}" for i in range(100)]
        chosen = a.packages if a.packages else sample_packages(pkgs, a.n, a.seed)
        print(f"Sample plan: {len(chosen)} package(s) (seed={a.seed}): {', '.join(chosen)}")
        print("Dry-run requested; no checkout performed.")
        return 0

    pkgs = list_available_packages()

    if a.list:
        print(f"Total available packages in pypi_malregistry: {len(pkgs):,}")
        for p in pkgs[:40]:
            print(f"  {p}")
        if len(pkgs) > 40:
            print(f"  ... and {len(pkgs) - 40:,} more")
        return 0

    chosen = a.packages if a.packages else sample_packages(pkgs, a.n, a.seed)
    print(f"Sample plan: {len(chosen)} package(s) (seed={a.seed}): {', '.join(chosen)}")


    # Configure sparse checkout
    subprocess.run(["git", "-C", str(MR_DIR), "sparse-checkout", "init", "--cone"], check=True)
    subprocess.run(["git", "-C", str(MR_DIR), "sparse-checkout", "set", *chosen], check=True)
    subprocess.run(["git", "-C", str(MR_DIR), "-c", "core.protectNTFS=false", "checkout", "main"], check=True)

    # Safe extract archives
    labels_list: list[dict] = []
    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)

    for pkg_name in chosen:
        pkg_dir = MR_DIR / pkg_name
        if not pkg_dir.exists():
            continue

        archives = list(pkg_dir.rglob("*.tar.gz")) + list(pkg_dir.rglob("*.zip")) + list(pkg_dir.rglob("*.whl"))
        target_extract = EXTRACTED_DIR / pkg_name
        if archives:
            for arch in archives:
                ver_dir = target_extract / arch.parent.name
                safe_extract_archive(arch, ver_dir)
                root = find_pkg_root(ver_dir, pkg_name)
                rel_path = root.relative_to(ROOT).as_posix()
                labels_list.append({
                    "id": pkg_name,
                    "path": rel_path,
                    "label": "malicious",
                    "category": "malregistry",
                    "claim": f"Malregistry backup package {pkg_name}",
                    "expected_verdict": "MALICIOUS-EVIDENT",
                    "notes": f"pypi_malregistry sample {pkg_name} ({arch.name}); NO LICENSE, local only",
                })
                break
        else:
            # Already directory format
            root = find_pkg_root(pkg_dir, pkg_name)
            rel_path = root.relative_to(ROOT).as_posix()
            labels_list.append({
                "id": pkg_name,
                "path": rel_path,
                "label": "malicious",
                "category": "malregistry",
                "claim": f"Malregistry backup package {pkg_name}",
                "expected_verdict": "MALICIOUS-EVIDENT",
                "notes": f"pypi_malregistry sample {pkg_name}; NO LICENSE, local only",
            })

    out_file = Path(a.out_labels)
    if labels_list:
        data = {"version": 1, "packages": labels_list}
        validate("bench_labels", data)
        out_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        print(f"Generated {len(labels_list)} malregistry labels -> {out_file}")

    print("Reminder: pypi_malregistry samples are local-only under data/ and MUST NEVER be committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
