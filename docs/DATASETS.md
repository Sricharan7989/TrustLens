# DATASETS (Owner: Dev C) — what we use, how, and what we must not claim

Priority order. All data under gitignored `data/`. Datasets are for **testing & calibration, not training**.

| # | Source | Use | Command | Notes |
|---|---|---|---|---|
| 1 | **PS1-Bench** (ours): 8–10 planted malicious toys + 15–20 clean controls | primary eval, heatmap | `bench/packages/**`, `bench/labels.yaml` | toys synthetic, RFC 5737 only |
| 2 | Top-PyPI clean list (hugovk) | clean controls (FP rate) | `bash scripts/fetch_clean_list.sh 30` | `curl -L`; sdist/wheel via PyPI JSON API + sha256; never pip install |
| 3 | Datadog malicious-software-packages-dataset, PyPI `malicious_intent`, 100–200 sample, seed 1337 | external recall | `bash scripts/fetch_datadog_sample.sh 150` (`--dry-run` first) | sparse checkout only; zip password `infected`; extract with `scripts/extract_in_sandbox.sh`; do not download the repo zip |
| 4 | QUT-DV25 (2.14 GB, Harvard Dataverse file 11542393) | benign-noise whitelist calibration (optional) | `bash scripts/fetch_qut.sh`; `bench/calibration/build_noise_whitelist.py` | **column format unverified**: inspect first |
| 5 | OSPtrack `label_data_v2.csv` (zenodo 21853840) | only if time | `bash scripts/fetch_osptrack.sh` | CC-BY-4.0 |
| 6 | pypi_malregistry | backup malicious pool | `bash scripts/fetch_malregistry.sh <pkg…>` | no license: local only |
| – | MalwareBench, MPAD-NPM | **skipped** | | |

Fixtures for external samples: after a live run, copy `raw_events.jsonl`+`run_meta.json` to `schemas/examples/<name>/` only through the lead (contract folder) — or keep external-sample results only in `reports/` (gitignored) and record aggregate numbers in `reports/eval/results.json`.
Match clean and malicious size distributions (`bench/tools/size_report.py`) so "tiny package = malicious" is not learned by the rules.

## Evaluation Harness (`eval/run_eval.py`)

Run commands:
- `make eval` (replay fixture stubs: fast, offline, deterministic)
- `make eval-live` (dynamic rootless bwrap sandbox execution in parallel, $\le 4$ workers)

Evaluation datasets evaluated during live evaluation:
1. **PS1-Bench planted toys** (`bench/labels.yaml`): 10 synthetic planted packages covering trigger $\times$ gate $\times$ obfuscation.
2. **PS1-Bench clean controls** (`bench/labels.yaml`): 16 clean controls (8 standard controls + 8 noisy-benign packages performing system inspection, network downloads, subprocess execution, SSH config reads).
3. **Top-PyPI clean set** (`bench/labels_external.yaml`): 30 popular real-world packages downloaded via PyPI JSON API with SHA-256 verification.
4. **Datadog PyPI malware sample** (`bench/labels_datadog.yaml`): 150 real-world malware packages sampled reproducibly (seed 1337).

### Statistical and Methodological Integrity
- **Recall Separation:** Synthetic planted toy recall is reported strictly separately from real-world external malware recall. We never combine them into a single misleading headline number.
- **Wilson 95% Score Intervals:** False positive rates are reported as $k/n$ with two-sided Wilson 95% confidence intervals ($0/n$ is never claimed as "0% FP").
- **Abstention Integrity:** Packages that fail installation, lack dynamic coverage, or return `INCONCLUSIVE` are recorded as abstentions, never disguised as clean PASS or false positives.
- **AUDIT §6 Triage:** Every false positive and miss is triaged and classified into:
  - *(a) true noise* -> whitelist candidate
  - *(b) claim parser gap* -> intent keywords in `capabilities.yaml`
  - *(c) coverage thin / dead sample* -> abstention (`INCONCLUSIVE`)
  - *(d) engine gap* -> detection rule candidate
  The triage log is written to `reports/eval/triage.md`.

