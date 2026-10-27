"""Dev C: Analyze OSPTrack data_metrics.csv to cross-check real-world attack distributions and plan more toys.

Usage:
    python bench/tools/analyze_osptrack.py [--csv data/osptrack/data_metrics.csv] [--out reports/bench/osptrack_metrics.md]
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def analyze_metrics(csv_path: Path) -> dict:
    if not csv_path.exists():
        raise FileNotFoundError(f"OSPTrack metrics file not found: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    total_rows = len(rows)
    by_pkg_type = Counter(r.get("pkg_type", "unknown") for r in rows)

    pypi_rows = [r for r in rows if r.get("pkg_type") == "pypi"]
    npm_rows = [r for r in rows if r.get("pkg_type") == "npm"]

    pypi_triggers = Counter(r.get("trigger_mechanism", "unknown") for r in pypi_rows)
    pypi_hides = Counter(r.get("hide", "unknown") for r in pypi_rows)
    pypi_attacks = Counter(r.get("attack_type", "unknown") for r in pypi_rows)
    pypi_locations = Counter(r.get("location", "unknown") for r in pypi_rows)

    def _blob(row: dict) -> str:
        return " ".join(str(row.get(k) or "") for k in ("attack_type", "hide", "function", "trigger_mechanism")).lower()

    return {
        "total_rows": total_rows,
        "by_pkg_type": by_pkg_type,
        "pypi_count": len(pypi_rows),
        "npm_count": len(npm_rows),
        "pypi_triggers": pypi_triggers,
        "pypi_hides": pypi_hides,
        "pypi_attacks": pypi_attacks,
        "pypi_locations": pypi_locations,
        "pypi_stego": sum(1 for r in pypi_rows if "steganograph" in _blob(r)),
        "pypi_split": sum(1 for r in pypi_rows if "split" in _blob(r)),
        "pypi_c2": sum(1 for r in pypi_rows if "c2" in _blob(r)),
    }


def generate_report(stats: dict) -> str:
    pypi_n = stats["pypi_count"]

    lines = [
        "# OSPTrack Empirical Analysis & PS1-Bench Toy Planning (C10)",
        "",
        f"Empirical analysis of {stats['total_rows']:,} malicious packages from **OSPTrack** (`data_metrics.csv`, CC-BY-4.0).",
        "Used for empirical validation of the PS1-Bench coverage matrix and planning additional synthetic planted toys.",
        "",
        "## 1. Dataset Overview",
        f"- **Total Malicious Packages Analyzed:** {stats['total_rows']:,}",
        f"- **PyPI Packages:** {stats['pypi_count']:,} ({stats['pypi_count'] / stats['total_rows']:.1%})",
        f"- **npm Packages:** {stats['npm_count']:,} ({stats['npm_count'] / stats['total_rows']:.1%})",
        "",
        "| Ecosystem | Package Count | Percentage |",
        "|---|---|---|",
    ]
    for eco, count in stats["by_pkg_type"].most_common():
        pct = (count / stats["total_rows"]) * 100
        lines.append(f"| `{eco}` | {count:,} | {pct:.1f}% |")

    lines.extend([
        "",
        f"## 2. PyPI Attack Techniques & Mechanisms (N = {pypi_n:,})",
        "",
        "### A. Trigger Mechanisms",
        "| Trigger Mechanism | Count | Share (%) | PS1-Bench Mapping & Coverage |",
        "|---|---|---|---|",
    ])
    for trig, count in stats["pypi_triggers"].most_common():
        pct = (count / max(pypi_n, 1)) * 100
        # Map to PS1-Bench
        if "download" in trig.lower() or "installation" in trig.lower() or "install" in trig.lower():
            mapping = "PS1-Bench `install` is `evil_slug` only"
        elif "import" in trig.lower():
            mapping = "PS1-Bench `import` is `import_exfil`"
        elif "cli" in trig.lower() or "command" in trig.lower():
            mapping = "PS1-Bench `cli` is `cli_payload`"
        elif "network" in trig.lower() or "connection" in trig.lower() or "function" in trig.lower() or "usage" in trig.lower() or "call" in trig.lower():
            mapping = "PS1-Bench `call`: `delayed_slug`, `time_gate`, `host_gate`, `staged_dropper`, `env_harvester`, `obfuscated_xor`"
        else:
            mapping = "see PS1-Bench triggers in docs/DATASETS.md"
        lines.append(f"| {trig} | {count:,} | {pct:.1f}% | {mapping} |")

    lines.extend([
        "",
        "### B. Obfuscation & Hiding Techniques",
        "| Obfuscation Technique | Count | Share (%) | PS1-Bench Mapping & Coverage |",
        "|---|---|---|---|",
    ])
    for hide, count in stats["pypi_hides"].most_common():
        pct = (count / max(pypi_n, 1)) * 100
        if "base64" in hide.lower():
            mapping = "`obfuscation: base64` (`delayed_slug`)"
        elif "obfuscation" in hide.lower():
            mapping = "`obfuscation: xor / zlib` (`obfuscated_xor`)"
        elif "n/a" in hide.lower():
            mapping = "`obfuscation: none` (`evil_slug`, `pth_hook`, `env_harvester`)"
        elif "split" in hide.lower():
            mapping = "Planned: `split_payload`"
        elif "steganography" in hide.lower():
            mapping = "Planned: `asset_stego`"
        else:
            mapping = "Specialized variant"
        lines.append(f"| {hide} | {count:,} | {pct:.1f}% | {mapping} |")

    lines.extend([
        "",
        "### C. Attack Objectives",
        "| Attack Classification | Count | Share (%) | Detected Artifact Signals |",
        "|---|---|---|---|",
    ])
    for atk, count in stats["pypi_attacks"].most_common():
        pct = (count / max(pypi_n, 1)) * 100
        if "dropper" in atk.lower():
            sigs = "`download_exec`, `decoded_exec`"
        elif "typosquatting" in atk.lower():
            sigs = "`canary_access`, `network_unclaimed`"
        elif "c2" in atk.lower():
            sigs = "`network_unclaimed`, `env_differential`"
        else:
            sigs = "`exec_payload`, `canary_access`"
        lines.append(f"| {atk} | {count:,} | {pct:.1f}% | {sigs} |")

    lines.extend([
        "",
        "## 3. PS1-Bench Trigger Coverage",
        "Percentage shares in the tables above are computed from this CSV.",
        "PS1-Bench malicious toys use these triggers:",
        "- `install`: `evil_slug` only",
        "- `pth`: `pth_hook`",
        "- `import`: `import_exfil`",
        "- `cli`: `cli_payload`",
        "- `call`: `delayed_slug`, `time_gate`, `host_gate`, `staged_dropper`, `env_harvester`, `obfuscated_xor`",
        "",
        "## 4. Planned Planted Toys (Informed by OSPTrack Gaps)",
        "Based on OSPTrack patterns, the following synthetic packages are planned for PS1-Bench expansion:",
        "1. **`clip_stealer`** (Attack: Clipboard / Crypto theft, Trigger: `call`, Obfuscation: `none`):",
        "   - *Empirical origin:* OSPTrack `uurllib3` pattern (accesses clipboard or crypto wallet locations).",
        "   - *Signals:* `file_read_sensitive`, `clipboard_access`.",
        "2. **`asset_stego`** (Attack: Dropper, Trigger: `install`, Obfuscation: `steganography`):",
        f"   - *Empirical origin:* OSPTrack PyPI rows whose attack_type or hide mentions steganography ({stats.get('pypi_stego', 'not computed')} in this CSV).",
        "   - *Signals:* Reads binary trailer from asset PNG/data file, executes with `exec()`.",
        "3. **`split_payload`** (Attack: Exfiltration, Trigger: `import`, Obfuscation: `split`):",
        f"   - *Empirical origin:* OSPTrack PyPI rows whose attack_type or hide mentions split ({stats.get('pypi_split', 'not computed')} in this CSV).",
        "   - *Signals:* Assembles base64 payload chunks from multiple package submodules before exfiltrating.",
        "4. **`atexit_beacon`** (Attack: C2 communication, Trigger: `call`, Gate: `none`):",
        f"   - *Empirical origin:* OSPTrack PyPI rows whose attack_type mentions C2 ({stats.get('pypi_c2', 'not computed')} in this CSV).",
        "   - *Signals:* Registers `atexit.register(...)` to connect to C2 address upon interpreter shutdown.",
    ])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Analyze OSPTrack data_metrics.csv and plan new planted toys")
    ap.add_argument("--csv", default=str(ROOT / "data" / "osptrack" / "data_metrics.csv"), help="Path to data_metrics.csv")
    ap.add_argument("--out", default=str(ROOT / "reports" / "bench" / "osptrack_metrics.md"), help="Path to output markdown report")
    a = ap.parse_args(argv)

    csv_path = Path(a.csv)
    out_path = Path(a.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not csv_path.exists():
        report = (
            "# OSPTrack Empirical Analysis\n\n"
            "not computed\n\n"
            f"No CSV at `{csv_path}`.\n"
        )
        out_path.write_text(report, encoding="utf-8")
        print("not computed")
        return 0
    stats = analyze_metrics(csv_path)
    report = generate_report(stats)

    out_path = Path(a.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"OSPTrack analysis complete: {stats['total_rows']:,} packages analyzed ({stats['pypi_count']:,} PyPI). Report -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
