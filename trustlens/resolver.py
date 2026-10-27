"""Package resolver for TrustLens.
Resolves local paths, benchmark toy IDs, and remote PyPI packages by downloading and safely extracting them.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from trustlens.cli import ARCHIVE_EXTENSIONS, _extract_archive_safely, _find_package_root, _is_valid_package_dir

logger = logging.getLogger("trustlens.resolver")

CACHE_DIR = Path.home() / ".trustlens" / "cache"


@dataclass
class ResolvedPackage:
    name: str
    version: str
    local_path: Path
    source_type: str  # "local_dir", "local_archive", "benchmark_toy", "pypi"
    is_temporary: bool = False
    temp_dir: Optional[tempfile.TemporaryDirectory] = None
    summary: str = ""
    home_page: str = ""
    author: str = ""


def find_benchmark_package(name_or_id: str) -> Optional[Path]:
    """Check if name_or_id matches a known benchmark package in bench/packages/."""
    # Look in bench/packages/malicious/ and bench/packages/clean/
    workspace_root = Path(__file__).resolve().parent.parent
    bench_dir = workspace_root / "bench" / "packages"
    if not bench_dir.exists():
        return None

    normalized = name_or_id.lower().replace("-", "_").strip()
    for category in ("malicious", "clean"):
        candidate = bench_dir / category / normalized
        if candidate.is_dir():
            return candidate
        # Also check with original dashes
        cand_dash = bench_dir / category / name_or_id.strip()
        if cand_dash.is_dir():
            return cand_dash
    return None


def fetch_from_pypi(package_name: str) -> tuple[Path, dict]:
    """Fetch package metadata and latest archive from PyPI, returning extracted path and metadata."""
    pkg_clean = package_name.strip().lower()
    pypi_url = f"https://pypi.org/pypi/{pkg_clean}/json"

    req = urllib.request.Request(pypi_url, headers={"User-Agent": "TrustLens-Dependency-Security/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ValueError(f"Package '{package_name}' was not found on PyPI (HTTP 404).") from e
        raise ValueError(f"Failed to fetch metadata from PyPI for '{package_name}': HTTP {e.code}") from e
    except Exception as e:
        raise ValueError(f"Network error querying PyPI for '{package_name}': {e}") from e

    info = data.get("info", {})
    version = info.get("version", "latest")
    urls = data.get("urls", [])

    if not urls:
        raise ValueError(f"PyPI package '{package_name}' ({version}) has no downloadable distribution files.")

    # Select preferred distribution: sdist (source) is best for inspecting README & setup.py, otherwise wheel
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = sdist or urls[0]
    download_url = chosen.get("url")
    filename = chosen.get("filename", f"{pkg_clean}-{version}.tar.gz")

    if not download_url:
        raise ValueError(f"No valid download URL found for '{package_name}'.")

    # Download to cache
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    download_dir = CACHE_DIR / "downloads"
    extracted_dir = CACHE_DIR / "extracted" / f"{pkg_clean}-{version}"
    download_dir.mkdir(parents=True, exist_ok=True)

    archive_file = download_dir / filename
    if not archive_file.exists() or archive_file.stat().st_size == 0:
        dl_req = urllib.request.Request(download_url, headers={"User-Agent": "TrustLens/1.0"})
        with urllib.request.urlopen(dl_req, timeout=30) as dl_resp, open(archive_file, "wb") as f_out:
            shutil.copyfileobj(dl_resp, f_out)

    # Safe extraction
    if extracted_dir.exists():
        shutil.rmtree(extracted_dir, ignore_errors=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)

    extracted_root = _extract_archive_safely(archive_file, extracted_dir)
    return extracted_root, info


def resolve_package(target: str) -> ResolvedPackage:
    """Resolve a user input string to a local inspectable package root."""
    target_str = target.strip()

    # 1. Direct local file or directory
    cand_path = Path(target_str)
    if cand_path.exists():
        if cand_path.is_dir():
            return ResolvedPackage(
                name=cand_path.name,
                version="local",
                local_path=cand_path.resolve(),
                source_type="local_dir",
            )
        # Check archive
        if any(cand_path.name.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            td = tempfile.TemporaryDirectory(prefix="trustlens_resolve_")
            root = _extract_archive_safely(cand_path, Path(td.name))
            return ResolvedPackage(
                name=cand_path.stem.split("-")[0],
                version="archive",
                local_path=root,
                source_type="local_archive",
                is_temporary=True,
                temp_dir=td,
            )

    # 2. Benchmark toy packages (e.g. evil_slug, clean_slug, delayed_slug)
    bench_match = find_benchmark_package(target_str)
    if bench_match:
        return ResolvedPackage(
            name=bench_match.name,
            version="ps1-bench",
            local_path=bench_match.resolve(),
            source_type="benchmark_toy",
        )

    # 3. Remote PyPI package
    try:
        extracted_root, info = fetch_from_pypi(target_str)
        return ResolvedPackage(
            name=info.get("name", target_str),
            version=info.get("version", "latest"),
            local_path=extracted_root,
            source_type="pypi",
            summary=info.get("summary", ""),
            home_page=info.get("home_page", ""),
            author=info.get("author", ""),
        )
    except Exception as e:
        raise ValueError(
            f"Could not resolve package '{target_str}': "
            f"Not a valid local path, benchmark toy, or retrievable PyPI package. ({e})"
        ) from e
