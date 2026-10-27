# ARCHITECTURE (Owner: Dev D; keep in sync with AGENTS.md §2 and CONTRACTS.md)

## One-paragraph design
We do not guess whether code *looks* malicious. We **make the package run** in a sandbox that offers it bait (fake SSH key, AWS creds, npmrc, tokens), in several situations (install, fresh interpreter, import, each callable, CLI; dev vs CI; today vs +30 days), watch everything it touches, and compare that with what its README/metadata license. Evidence beats suspicion: a fake secret appearing inside an outgoing request is proof, not a score.

## Stages
1. **Sandbox (A)** — rootless `bwrap` (`--unshare-net/pid/uts/ipc`, `--clearenv`, fake HOME). Two profiles: `dev` (laptop camouflage) and `ci` (CI env vars, CI hostnames). Layers: (a) `sys.addaudithook` agent injected via `sitecustomize` (open, socket, subprocess, exec/compile, urllib), (b) an `os.environ` wrapper because CPython emits **no audit event for env reads**, (c) site-packages diff after a real offline `pip install` to catch `.pth`/`sitecustomize` startup hooks, (d) `strace` as a second layer for native code (needs baseline subtraction), (e) trigger matrix: install -> fresh-startup -> import-all -> call-all (typed dummy args) -> CLI entry points; clock+30d variant. Output `raw_events.jsonl` + `run_meta.json` incl. an honest `coverage.not_observed`.
2. **Normalizer (B)** — classify raw kinds into 12 capabilities, **attribute** each event (`pkg` / `toolchain` / `dep:<name>`: innermost non-stdlib frame), drop toolchain noise, subtract strace baseline, apply the calibrated noise whitelist, mark capabilities that only appear in some profiles (`conditional` = env-differential), emit `fingerprint.json`.
3. **Claim extractor (B)** — README/metadata/entry points -> intents (8) -> licensed capabilities (`capabilities.yaml`). Rule-based keyword mapping; unknown intent => nothing licensed, flagged.
4. **Mismatch engine (B)** — observed - licensed, weighted by severity x phase x (canary x2, env-differential x1.5, obfuscation x1.5). Ladder: `MALICIOUS-EVIDENT` needs canary-in-bytes or >= 2 independent strong signal classes; thin coverage => `INCONCLUSIVE`. Every finding carries event ids, file:line, claim quote, explanation sentence.
5. **CLI + report (D)** — `python -m trustlens scan`, accepts directory, wheel/sdist archives (safely extracted without execution), or `requirements.txt`; JSON + self-contained HTML (timeline by phase/profile, coverage block, evidence chains); exit codes 0/10/20/2. `make demo-all` verifies full suite against `bench/labels.yaml`. `make demo-compare` generates side-by-side verification reports.
6. **Bench + eval (C)** — PS1-Bench (planted toys over trigger x gate x obfuscation + clean controls), external samples (Datadog sample, top-PyPI clean), calibration from QUT-DV25 -> noise whitelist, harness vs TrustLens / GuardDog 3.2.0 / PipCanary 0.1.1, Wilson CIs, recall heatmap.

## CI & GitHub Actions Integration (SARIF 2.1.0)
TrustLens can run in continuous integration workflows and publish SARIF 2.1.0 alerts directly into GitHub Advanced Security Code Scanning:

```yaml
name: TrustLens Dependency Provenance
on: [pull_request, push]

jobs:
  provenance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install TrustLens
        run: pip install -r requirements.txt
      - name: Scan Dependencies
        run: |
          python -m trustlens scan requirements.txt --format sarif --out reports/ci
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/ci/report.sarif
```

## Why these choices (answers to judges)
* *Why not static analysis only?* Obfuscation/gating defeat it; GuardDog is our static baseline.
* *Why not a plain sandbox?* PipCanary exists; the novelty is **comparison against claims** + **env-differential** + **startup-hook-aware install** + **abstention**.
* *Why no LLM?* Reproducible, offline, auditable; judges can re-run and diff.
* *Why datasets for calibration not training?* Nothing is learned; thresholds are rules; datasets expose noise and measure recall.

## Known blind spots -> see `docs/LIMITATIONS.md`.
