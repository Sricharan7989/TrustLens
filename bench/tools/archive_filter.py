"""Extract zip, tar, and wheel archives with a data filter.

Symlinks, hard links, absolute paths, and ``..`` members are skipped. Safe
members are written only under the destination directory.
"""
from __future__ import annotations

import argparse
import os
import stat
import tarfile
import zipfile
from pathlib import Path

_INFECTED = b"infected"


def safe_relative_parts(name: str) -> tuple[str, ...] | None:
    """Return destination-relative parts, or None if the name is not a data member.

    Rejects absolute paths, drive paths, and any ``..`` component.
    """
    raw = name.replace("\\", "/")
    if "\x00" in raw:
        return None
    if raw.startswith("/") or raw.startswith("~"):
        return None
    if len(raw) >= 2 and raw[1] == ":":
        return None
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return tuple(parts)


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _open_zip_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo):
    if info.flag_bits & 0x1:
        return zf.open(info, pwd=_INFECTED)
    try:
        return zf.open(info)
    except RuntimeError:
        return zf.open(info, pwd=_INFECTED)


def _within_dest(dest: Path, target: Path) -> bool:
    if dest.is_symlink():
        return False
    try:
        target.resolve().relative_to(dest.resolve())
    except (OSError, ValueError):
        return False
    cur = dest
    for part in target.relative_to(dest).parts:
        cur = cur / part
        if cur.is_symlink():
            return False
    return True


def _mkdirs(dest: Path, parts: tuple[str, ...]) -> bool:
    cur = dest
    for part in parts:
        cur = cur / part
        if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
            return False
        cur.mkdir(exist_ok=True)
    return _within_dest(dest, cur)


def _write_bytes(dest: Path, parts: tuple[str, ...], reader) -> bool:
    if not _mkdirs(dest, parts[:-1]):
        return False
    target = dest.joinpath(*parts)
    if target.is_symlink() or target.is_dir():
        return False
    if not _within_dest(dest, target):
        return False
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(target, flags, 0o644)
    except OSError:
        return False
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
    except OSError:
        return False
    return _within_dest(dest, target)


def _extract_zip(archive: Path, dest: Path) -> bool:
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile:
        return False
    with zf:
        for info in zf.infolist():
            if _zip_is_symlink(info):
                continue
            parts = safe_relative_parts(info.filename)
            if parts is None:
                continue
            is_dir = info.is_dir() or info.filename.endswith("/") or info.filename.endswith("\\")
            try:
                if is_dir:
                    if not _mkdirs(dest, parts):
                        continue
                else:
                    with _open_zip_member(zf, info) as src:
                        if not _write_bytes(dest, parts, src):
                            continue
            except (RuntimeError, OSError, zipfile.BadZipFile):
                return False
    return True


def _tar_allowed(member: tarfile.TarInfo) -> bool:
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        return False
    return safe_relative_parts(member.name) is not None


def _extract_tar(archive: Path, dest: Path) -> bool:
    try:
        tf = tarfile.open(archive, mode="r:*")
    except tarfile.TarError:
        return False
    with tf:
        for member in tf.getmembers():
            if not _tar_allowed(member):
                continue
            try:
                tf.extract(member, path=dest, set_attrs=False, filter="data")
            except (tarfile.FilterError, tarfile.ExtractError, OSError):
                continue
    if any(p.is_symlink() for p in dest.rglob("*")):
        return False
    return True


def extract_archive_filtered(archive_path: Path, target_dir: Path) -> bool:
    """Extract ``archive_path`` into ``target_dir`` using the data filter.

    Returns False when the archive cannot be read. Rejected members are skipped
    and nothing is written outside ``target_dir``.
    """
    archive_path = Path(archive_path)
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    if target_dir.is_symlink():
        return False
    name = archive_path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return _extract_tar(archive_path, target_dir)
    if name.endswith((".zip", ".whl")):
        return _extract_zip(archive_path, target_dir)
    return False


def main(argv: list[str] | None = None) -> int:
    """CLI used by scripts/extract_in_sandbox.sh inside bwrap."""
    ap = argparse.ArgumentParser(description="Extract an archive with a data filter")
    ap.add_argument("archive")
    ap.add_argument("dest")
    args = ap.parse_args(argv)
    ok = extract_archive_filtered(Path(args.archive), Path(args.dest))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
