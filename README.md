# TrustLens AI

**PS1 "Trust Nothing: Provenance for Your Own Dependencies"** — IOTA × Enigma hackathon, IIIT Sri City, Cybersecurity track.

TrustLens runs a Python package inside a **no-network sandbox with fake secrets (canaries)**, records what it *actually does* at install, interpreter startup, import, call and CLI, under a *dev-laptop* and a *CI* environment, compares that with what its **README/metadata claim**, and prints a verdict with an **evidence chain** and an honest **coverage** block. Rule-based, deterministic, offline, no LLM in the verdict path.

Verdicts: `MALICIOUS-EVIDENT` (exit 20) · `SUSPICIOUS` (10) · `INCONCLUSIVE` (10, we abstain when we could not observe enough) · `BENIGN-CONSISTENT` (0, "consistent with stated purpose within the listed coverage", not "safe").

## Quickstart (3 steps)
```bash
git clone <repo> && cd trustlens
make setup-dev            # 1. venv + pinned deps (+ GuardDog/PipCanary baselines); needs python3-venv
make demo                 # 2. scans 4 toy packages end to end on recorded fixtures -> reports/demo/*/report.html
make demo-all             # 3. scans all benchmark packages and prints verification table
make demo-compare         # 4. generates side-by-side comparison (clean vs malicious) -> reports/compare_demo.html
make serve                # 5. launches local Web UI console at http://127.0.0.1:8765/
make eval                 # 6. PS1-Bench metrics + heatmap vs baselines -> reports/eval/summary.md, heatmap.html
```

*Note:* On Ubuntu/Debian, ensure `python3-venv` is installed (`sudo apt install python3-venv python3-pip`).

## Real sandbox (toys only!)
Run `bash scripts/check_env.sh` then `make demo-live`. Needs `bubblewrap` (`sudo apt install bubblewrap strace`). On Ubuntu 24.04 you may need the unprivileged user namespace workaround that the check script prints.

## Input & Command Support
TrustLens CLI accepts:
1. **Package directories**: `python -m trustlens scan bench/packages/malicious/evil_slug`
2. **Wheel / sdist archives**: `python -m trustlens scan dist/package-1.0.whl` (extracted safely without code execution)
3. **Requirements files**: `python -m trustlens scan requirements.txt` (scans all local path references offline)
4. **Baseline comparison**: `python -m trustlens scan bench/packages/malicious/evil_slug --compare` (compares with GuardDog & PipCanary)
5. **Behavioral diff between versions**: `python -m trustlens diff bench/packages/clean/clean_slug bench/packages/malicious/evil_slug`
6. **Localhost Web Console**: `python -m trustlens serve --port 8765` (100% offline, zero CDN dependencies)

## CI / CD & Pre-commit Integrations

### 1. `pre-commit` Hook (`.pre-commit-config.yaml`)
To block malicious or anomalous dependency updates prior to commit:
```yaml
repos:
  - repo: local
    hooks:
      - id: trustlens-audit
        name: TrustLens Dependency Provenance
        entry: python -m trustlens scan
        language: system
        files: (requirements\.txt|setup\.py|pyproject\.toml)$
        pass_filenames: true
```

### 2. GitHub Actions Workflow (SARIF 2.1.0 Code Scanning)
```yaml
name: Dependency Provenance Scan
on: [pull_request, push]

jobs:
  trustlens-provenance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - name: Scan Dependencies
        run: python -m trustlens scan requirements.txt --format sarif --out reports/ci
      - name: Publish SARIF Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/ci/report.sarif
```

## Status: starter kit (what is real and what is stubbed)
| Part | Status |
|---|---|
| Contracts, schemas, fixtures, tests, audit | real |
| Sandbox live runner (bwrap, canaries, dev/ci, `setup.py egg_info`, import-all, call-all, audit hook, env wrapper, real `pip install` + `.pth` diff, fresh-startup, strace, clock+30d, CLI trigger, loopback sinkhole) | **implemented** — see `docs/SANDBOX.md` (Docker fallback is implemented, not executed on the sandbox VM) |
| Claims extractor, normalizer, rules, verdict ladder | **v0 real** (keyword intents, 10 rules) — Dev B extends |
| Report (HTML/JSON/text/SARIF), CLI orchestrator, Web UI | **v2.0 real** (interactive timeline filters, evidence chains, web UI console, SARIF 2.1.0) — Dev D |
| PS1-Bench | 4 starter packages — Dev C grows to 8–10 malicious + 15–20 clean |
| `make demo` / `make eval` | run on **recorded fixtures** (real bwrap recordings of the toys); marked `stub:true` in `run_meta` |

## Layout & how to work
Read **`AGENTS.md`** (ownership, rules), **`docs/CONTRACTS.md`** (interfaces), then your prompt in **`prompts/`**. Four devs A–D own disjoint folders; the lead merges. `AUDIT.md` + `make audit` guard safety, licensing and claims. `DEPENDENCIES.md` lists every dependency (and the `supply-chain-guard` name trap). `docs/` has architecture, limitations, demo script, and the PPT outline.

## Safety
Malware samples never run on the host: only inside bwrap, network off, fake HOME, data in gitignored `data/`. Never `pip install supply-chain-guard`. Packj is AGPL: never copied.

The scan output directory is not uniformly redacted. `verdict.json`, `fingerprint.json`, `claims.json`, and `report.*` (HTML, JSON, and SARIF) have canary token bytes removed. `raw_events.jsonl` and `run_meta.json` are the raw sandbox logs and still contain the fake `TLCANARY` token strings. Do not share those two files as-is.

## AI-assistance disclosure
This repo was scaffolded with coding agents for a hackathon; every dev reviews generated diffs. License: MIT.
