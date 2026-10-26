"""Dev C: size/age mix of a package folder set so the clean set matches the malicious set (avoid 'tiny = bad' shortcut)."""
import sys
from pathlib import Path


def size_kb(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) // 1024


if __name__ == "__main__":
    root = Path(sys.argv[1])
    sizes = sorted(size_kb(d) for d in root.iterdir() if d.is_dir())
    if sizes:
        print(f"n={len(sizes)} min={sizes[0]}KB median={sizes[len(sizes)//2]}KB max={sizes[-1]}KB")
