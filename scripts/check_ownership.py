#!/usr/bin/env python3
"""Fail if the current branch changed files its owner does not own (OWNERS.yaml).  python scripts/check_ownership.py --dev a [--base origin/main]
The lead branch ('lead/...') may touch anything listed under owner 'lead' AND may merge for others. Used by the PM before every merge."""
import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--dev", required=True, choices=["a", "b", "c", "d", "lead"])
ap.add_argument("--base", default="main")
a = ap.parse_args()
owners = yaml.safe_load((ROOT / "OWNERS.yaml").read_text())["owners"]
changed = subprocess.run(["git", "diff", "--name-only", f"{a.base}...HEAD"], capture_output=True, text=True, cwd=ROOT, check=True).stdout.split()
bad = []
for f in changed:
    owner = next((o for o, globs in owners.items() if any(fnmatch.fnmatch(f, g) or f.startswith(g.rstrip("*")) for g in globs)), None)
    if owner != a.dev:
        bad.append((f, owner))
for f, o in bad:
    print(f"NOT YOURS: {f} (owner: {o})")
print(f"{len(changed)} changed file(s), {len(bad)} outside ownership of '{a.dev}'")
sys.exit(1 if bad else 0)
