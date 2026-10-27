"""Dev C: turn benign install/import traces (QUT-DV25 or OSPtrack) into a noise whitelist for the normalizer.

python bench/calibration/build_noise_whitelist.py [--csv data/qut/QUT-DV25_Filetop_Traces.csv] [--label-col Level] [--benign-value 0]
      [--cols Read_Processes Write_Processes File_Access_Processes] [--min-prevalence 0.02] [--out bench/calibration/noise_whitelist.yaml]

A token is whitelisted when it occurs in >= min-prevalence of BENIGN rows AND in < 1/4 of that prevalence of malicious rows (rare-in-malware noise only).
Safety invariant (AUDIT §6): no whitelist rule may match canary tokens, sensitive credential files, or RFC 5737 targets.
Output schema = trustlens/engine/noise_whitelist.yaml rules: {capability, path_glob|host_glob|env_glob, reason, source, benign_prevalence?}.
benign_prevalence is omitted on source: seed rules. It is set only from CSV row counts.
Subprocess path_glob rules are not emitted: proc.spawn records argv, not path.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.tools.cross_check_whitelist import ADVERSARIAL_PROBES, strings_matched_by  # noqa: E402
from trustlens.fingerprint.normalize import SECRET_ENV  # noqa: E402

CAP_OF = {
    "processes": ("subprocess", "path_glob"),
    "read_processes": ("subprocess", "path_glob"),
    "write_processes": ("subprocess", "path_glob"),
    "file_access_processes": ("subprocess", "path_glob"),
    "files": ("fs_read_sensitive", "path_glob"),
    "sockets": ("network", "host_glob"),
    "dns": ("network", "host_glob"),
    "commands": ("subprocess", "path_glob"),
    "import_files": ("fs_read_sensitive", "path_glob"),
    "install_files": ("fs_read_sensitive", "path_glob"),
    "import_sockets": ("network", "host_glob"),
    "install_sockets": ("network", "host_glob"),
    "import_commands": ("subprocess", "path_glob"),
    "install_commands": ("subprocess", "path_glob"),
    "import_dns": ("network", "host_glob"),
    "install_dns": ("network", "host_glob"),
}

FORBIDDEN_PATTERNS = re.compile(
    r"(id_rsa|\.ssh|\.aws|\.npmrc|\.pypirc|canary|198\.51\.100|203\.0\.113|192\.0\.2|invalid|token|secret|password)",
    re.I,
)

# proc.spawn detail is argv, not path. These path_globs cannot match it, and neither can any other subprocess path_glob.
UNMATCHABLE_PROC_GLOBS = {
    "*python*",
    "*ld*",
    "*clear*",
    "*strace*",
    "*cc1*",
    "*pip3*",
    "*systemd-oomd*",
    "*ThreadPoolForeg*",
    "*cc1plus*",
}


def parse_cell(cell: str) -> set[str]:
    """Split comma, semicolon, newline, or pipe-separated cell values, or parse OSPTrack dicts."""
    if not cell or cell in ("[]", "{}"):
        return set()
    if "'Path':" in cell or "'Hostname':" in cell or "'Address':" in cell or "'Command':" in cell:
        tokens: set[str] = set()
        for m in re.finditer(r"'(?:Path|Hostname|Address)':\s*'([^']+)'", cell):
            tokens.add(m.group(1))
        for m in re.finditer(r"'Command':\s*(?:array\(\[)?'([^']+)'", cell):
            tokens.add(m.group(1))
        if tokens:
            return tokens
    return {t.strip() for t in re.split(r"[;\n|]|\s{2,}|,\s*", cell or "") if t.strip()}


def is_safe_rule(cap: str, key: str, val: str) -> bool:
    """Ensure no rule can suppress canary hits or planted malware signals."""
    if FORBIDDEN_PATTERNS.search(val):
        return False
    return True


def glob_is_exact_enough(key: str, glob_pat: str) -> bool:
    """Reject globs that match an adversarial probe, and env globs that name a secret."""
    if set(strings_matched_by(glob_pat)) & set(ADVERSARIAL_PROBES):
        return False
    if key == "env_glob" and SECRET_ENV.search(glob_pat):
        return False
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate noise whitelist from benign vs malicious traces (calibration only, not training)")
    ap.add_argument("--csv", default="data/qut/QUT-DV25_Filetop_Traces.csv", help="Path to trace CSV file(s), comma-separated")
    ap.add_argument("--label-col", default="Level", help="Column containing class label (Level or Label)")
    ap.add_argument("--benign-value", default="0", help="Value representing benign class in label-col")
    ap.add_argument(
        "--cols",
        nargs="+",
        default=["Read_Processes", "Write_Processes", "File_Access_Processes"],
        help="Column(s) to analyze for noise tokens",
    )
    ap.add_argument("--min-prevalence", type=float, default=0.02, help="Minimum prevalence in benign set (default: 0.02)")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of rows read per CSV (0 = all)")
    ap.add_argument("--out", default="bench/calibration/noise_whitelist.yaml", help="Output YAML path")
    a = ap.parse_args(argv)

    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2147483647)

    csv_paths = [Path(p.strip()) for p in a.csv.split(",") if p.strip()]
    ben: dict[str, Counter] = {c: Counter() for c in a.cols}
    mal: dict[str, Counter] = {c: Counter() for c in a.cols}
    nb = nm = 0

    for csv_path in csv_paths:
        if not csv_path.exists():
            print(f"warning: CSV not found: {csv_path}", file=sys.stderr)
            continue
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if a.limit and i >= a.limit:
                    break
                is_ben = str(row.get(a.label_col, "")).strip() == str(a.benign_value).strip()
                if is_ben:
                    nb += 1
                else:
                    nm += 1
                for c in a.cols:
                    if c in row:
                        tokens = parse_cell(row.get(c, ""))
                        (ben if is_ben else mal)[c].update(tokens)

    rules: list[dict] = []
    seen_globs: set[tuple[str, str]] = set()

    # Seed rules are not measurements. Prevalence is attached only when a CSV computes it.
    calibrated_seeds = [
        {
            "capability": "network",
            "host_glob": "127.0.0.1",
            "reason": "exact loopback address used by local unit test servers and clients",
            "source": "seed",
        },
        {
            "capability": "network",
            "host_glob": "localhost",
            "reason": "exact localhost hostname used by local test servers",
            "source": "seed",
        },
        {
            "capability": "env_secrets",
            "env_glob": "PYTEST_CURRENT_TEST",
            "reason": "pytest current-test name; does not match secret env names",
            "source": "seed",
        },
        {
            "capability": "env_secrets",
            "env_glob": "TOX_ENV_NAME",
            "reason": "tox environment name; does not match secret env names",
            "source": "seed",
        },
    ]

    for seed in calibrated_seeds:
        key = "host_glob" if "host_glob" in seed else "env_glob"
        if not glob_is_exact_enough(key, seed[key]):
            continue
        seen_globs.add((seed["capability"], seed[key]))
        rules.append(seed)

    # Derive empirical rules from benign vs malicious trace ratios
    for c in a.cols:
        col_key = c.lower()
        cap, key = CAP_OF.get(col_key, (None, None))
        if not cap:
            for k_prefix in CAP_OF:
                if col_key.endswith(k_prefix):
                    cap, key = CAP_OF[k_prefix]
                    break
        if not cap or not key:
            continue

        for tok, count in ben[c].most_common(200):
            pb = count / max(nb, 1)
            pm = mal[c][tok] / max(nm, 1)
            if pb >= a.min_prevalence and pm < pb / 4:
                # host and env globs are exact tokens. A wrapped *glob* also matches lookalikes.
                if key in ("host_glob", "env_glob"):
                    glob_pat = tok
                else:
                    glob_pat = tok if tok.startswith("*") else f"*{tok}*"
                # path_glob is matched against detail["path"]. proc.spawn has argv, so these rules never fire.
                if cap == "subprocess" and key == "path_glob":
                    continue
                if glob_pat in UNMATCHABLE_PROC_GLOBS:
                    continue
                if not is_safe_rule(cap, key, glob_pat):
                    continue
                if not glob_is_exact_enough(key, glob_pat):
                    continue
                rule_key = (cap, glob_pat)
                measured = {
                    "capability": cap,
                    key: glob_pat,
                    "reason": f"benign prevalence {pb:.1%} vs malicious {pm:.1%} in trace dataset",
                    "source": f"{Path(csv_paths[0]).name}:{c}",
                    "benign_prevalence": round(pb, 4),
                }
                if rule_key in seen_globs:
                    for i, existing in enumerate(rules):
                        if existing.get("capability") == cap and existing.get(key) == glob_pat and existing.get("source") == "seed":
                            rules[i] = measured
                            break
                    continue
                seen_globs.add(rule_key)
                rules.append(measured)

    out_path = Path(a.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = "# generated by build_noise_whitelist.py (calibration only, not training)\n"
    out_path.write_text(header + yaml.safe_dump({"rules": rules}, sort_keys=False), encoding="utf-8")
    print(f"{nb} benign / {nm} malicious rows -> {len(rules)} whitelist rules -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
