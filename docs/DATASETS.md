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

## Noise-Whitelist Calibration (`bench/calibration/build_noise_whitelist.py`)

Calibration dataset: **QUT-DV25** (Harvard Dataverse 11542393, 14,271 trace records: 7,144 benign and 7,127 malicious packages).

- **Calibration, not training:** QUT-DV25 trace records are used solely to calibrate benign build/runtime noise thresholds (frequency filtering for common toolchain sub-processes and local loopback/test signals). No machine learning model is trained on these datasets.
- **Rule criterion:** A token is whitelisted only if it occurs in $\ge 2\%$ of benign trace records AND in $< \frac{1}{4}$ of that prevalence in malicious trace records (rare-in-malware noise only).
- **Canary invariant (AUDIT §6):** No rule in `noise_whitelist.yaml` may ever match canary tokens, sensitive credential paths (`.ssh`, `.aws`, `.npmrc`), or RFC 5737 targets.
- **Generated output:** `bench/calibration/noise_whitelist.yaml`, which is merged dynamically by the fingerprint normalizer (`trustlens/fingerprint/normalize.py`).

## Baseline Adapters (GuardDog, PipCanary, Packj)

Baseline adapters live under `eval/baselines/` and provide uniform comparison against established tools.

### 1. GuardDog 3.2.0 (Static Baseline)
- **License:** Apache-2.0.
- **Invocation:** `guarddog pypi scan <pkg_dir> --output-format json -x typosquatting -x potentially_compromised_email_domain -x unclaimed_maintainer_email_domain`
- **Network-dependent rule exclusions (Offline Integrity):**
  1. `typosquatting`: queries PyPI API for similar popular package names.
  2. `potentially_compromised_email_domain`: performs DNS WHOIS queries to inspect domain creation dates.
  3. `unclaimed_maintainer_email_domain`: performs DNS MX record queries to check domain expiration.
  Excluding these 3 network rules ensures reproducible, fully offline static evaluation on local package directories.
- **Rules evaluated:** All offline AST, Semgrep, and YARA rules (e.g. code execution, obfuscation, shady URLs, exfiltration).

### 2. PipCanary 0.1.1 (Dynamic Sandbox Baseline)
- **License:** MIT.
- **Prerequisites:** `pipcanary`, `bwrap`, and `strace` on PATH.
- **Shared Host Network Caveat & Safety Invariant:**
  PipCanary executes `pip install` with the **host network SHARED** (it is a baseline detector, not our isolated sandbox).
  - **Permitted targets:** Run only on clean packages and synthetic planted toys on throwaway test machines.
  - **Forbidden targets:** **NEVER run PipCanary on real or external malware samples** (`data/datadog/**`, `data/malregistry/**`) unless inside Docker with `--network none` isolation.
  - **Adapter guardrail:** The adapter automatically detects external malware paths and refuses to execute on the host network, returning `flagged: None` with a safety explanation.

### 3. Packj (AGPL-3.0 CLI-Only Baseline)
- **License:** AGPL-3.0.
- **Legal & Architectural Isolation:**
  In strict accordance with project licensing constraints:
  - **Zero code copied:** No Packj source code or modified code is present in this repository.
  - **Zero code imported:** Python never imports any `packj` modules.
  - **CLI subprocess only:** Optional adapter that invokes `packj audit <pkg_dir> --output-format json` via `subprocess.run` if installed on PATH; otherwise cleanly skipped.

### 4. Adapter Contract & "Not Run" Protocol
Every baseline adapter implements:
```python
run(pkg_dir: str | Path, timeout_s: int) -> dict
```
Returning a standardized dictionary conforming to:
- `available`: `bool` (`False` if the tool or required binary is missing from PATH)
- `flagged`: `bool | None` (`None` when unavailable, inconclusive, or on error)
- `rules`: `list[str]` (names of triggered detection rules or alerts)
- `runtime_s`: `float | None`
- `error`: `str | None`

**Rendering invariant:**
If a tool reports `available: False`, the harness renders it as `"not run"` in both `summary.md` and `heatmap.html`. Unavailable tools are **never reported as 0 detections or 0% FP rate**.

## Held-Out Evaluation Split (C9)

To ensure methodological rigor and protect against rule overfitting, **10 packages (5 clean + 5 malicious)** are designated as the held-out split (`bench/held_out.yaml`).

### Composition of the Held-Out Split
- **Clean Controls (5):**
  1. `math_lib`: Pure numerical vector math and arithmetic routines.
  2. `color_text`: ANSI terminal color text styling.
  3. `json_parser`: Lightweight JSON parser and text validator.
  4. `case_converter`: String case formatting (camelCase, snake_case, kebab-case).
  5. `date_calc`: Datetime delta arithmetic and calendar calculations.
- **Malicious Toys (5):**
  1. `cli_payload`: CLI entry point trigger reading `~/.ssh/id_rsa` and contacting RFC 5737 testnet.
  2. `staged_dropper`: Staged downloader fetching second-stage payload from `payload.invalid`.
  3. `env_harvester`: Gathers credentials from `os.environ` and resolves DNS to `exfil.invalid`.
  4. `obfuscated_xor`: XOR/`chr()`-obfuscated payload executed dynamically.
  5. `time_gate`: Dormant bomb gated by calendar date (> now + 15 days).

### Methodological Isolation
- **Zero Tuning Exposure:** These 10 packages were completely isolated from the initial tuning set (`evil_slug`, `delayed_slug`, `clean_slug`, `rest_wrapper`, `_synthetic_pth_startup`).
- **No Rule or Threshold Calibration:** No detection rule, claim parser intent keyword, or noise-whitelist token was created or calibrated against these packages.
- **Execution:** Can be evaluated individually via `python -m eval.run_eval --labels bench/held_out.yaml` or as part of full benchmark runs.

## OSPTrack Dataset & Empirical Toy Planning (C10)

OSPTrack (Zenodo record 21853840, CC-BY-4.0) provides empirical metadata and execution traces across 20,269 open-source supply chain attacks.

### 1. Dataset Components
- **`data_metrics.csv` (2.7 MB):** Classification metadata for 20,269 malicious packages (6,683 PyPI, 13,565 npm) covering attack objectives, trigger mechanisms, and obfuscation methods.
- **`label_data_v2.csv` (1.76 GB):** Dynamic trace execution records across 18 columns (`import_Files`, `import_Sockets`, `import_Commands`, `import_DNS`, `install_*`, `Label`). MD5 verified against `1d3aeaa9e1b338603c2f4ce8e6f5d68c`.
- **Fetch script:** `bash scripts/fetch_osptrack.sh` (`--metrics-only`, `--check-only`, or full download).

### 2. Empirical PyPI Attack Distributions (N = 6,683)
Analysis performed by `python bench/tools/analyze_osptrack.py` (`reports/bench/osptrack_metrics.md`):
- **Triggers:**
  - *Automatic execution upon download/install:* 95.2% (5,460 download + 900 installation).
  - *Runtime network connection:* 4.2% (283 packages).
  - *Function call / usage:* 0.5% (31 packages).
- **Hiding & Obfuscation:**
  - *Base64 encoding:* 81.1% (5,423 packages).
  - *General obfuscation (XOR, eval, hex):* 13.5% (900 packages).
  - *Plain / un-obfuscated:* 4.7% (312 packages).
  - *Steganography & split payloads:* 0.7% (48 packages).
- **Attack Types:**
  - *Droppers & second-stage loaders:* 81.1% (5,423 packages).
  - *Typosquatting & credential harvesting:* 14.5% (968 packages).
  - *C2 communication & persistent beacons:* 4.2% (283 packages).

### 3. PS1-Bench Matrix Validation & Expansion Plan
OSPTrack empirical findings validate the core architecture of PS1-Bench:
- **Trigger alignment:** 4/10 planted toys focus on install-time execution (`evil_slug`, `staged_dropper`, `obfuscated_xor`, `pth_hook`), mirroring the 95.2% real-world concentration.
- **Obfuscation alignment:** Base64 decoding (`delayed_slug`) and XOR dynamic evaluation (`obfuscated_xor`) cover the dominant real-world obfuscation vectors.
- **Planned expansion toys:**
  1. `clip_stealer`: Clipboard access and cryptocurrency address hijacking (OSPTrack `uurllib3` pattern).
  2. `asset_stego`: Hiding payloads within package image assets (OSPTrack `steganography/obfuscation`).
  3. `split_payload`: Distributing payload fragments across submodules (OSPTrack `split payloads`).
  4. `atexit_beacon`: Registering interpreter termination hooks for C2 exfiltration (OSPTrack `C2 communication`).

### 4. Benign-Trace Whitelist Cross-Check
Verified via `python bench/tools/cross_check_whitelist.py`:
- All 12 calibrated rules in `bench/calibration/noise_whitelist.yaml` were cross-checked against benign trace schemas.
- **AUDIT §6 Invariant Verified:** Zero whitelist rules match canary tokens, SSH/AWS/npm credential files, RFC 5737 targets, or `.invalid` test domains.

## Malregistry Backup Dataset (C11)

Backup malicious pool sourced from `lxyeternal/pypi_malregistry`. Used as a supplementary / contingency malware pool to test real-world malware topologies (e.g., typosquatting, credential harvesting, discord token stealers) alongside the primary Datadog dataset.

### 1. Strict Licensing & Distribution Invariants
- **NO LICENSE:** The `pypi_malregistry` repository has **no license**.
- **Local-only Invariant:** All repository clones, archives, and extracted packages MUST remain strictly local under `data/malregistry/` (which is gitignored).
- **NEVER Commit or Redistribute:** Sample source code, binaries, or artifacts from `pypi_malregistry` must NEVER be committed to version control, pushed to public remotes, or redistributed in slides/reports.
- **Testing Only:** Samples are used exclusively for offline detection testing and calibration, never for model training or active execution.

### 2. Host Safety & Sandbox Isolation
- **No Host Execution:** Malware samples must never be executed directly on the host machine (`python setup.py`, `pip install`, etc. on the host are strictly forbidden).
- **Safe Sandbox Extraction:** Package archives (`.tar.gz`, `.zip`, `.whl`) are extracted using `scripts/extract_in_sandbox.sh` (rootless `bwrap` container without network access or host file-system write permissions).
- **Path-Traversal Protection:** The fallback Python extractor validates all member paths, rejecting any archive entries containing absolute paths or directory traversal segments (`..`).

### 3. Blobless Sparse Checkout Protocol
- **Bandwidth & Storage Optimization:** The full repository contains thousands of malware archives (~1.4 GB). We **never download the entire repository or repo zip**.
- **Blobless Shallow Clone:**
  ```bash
  git clone --filter=blob:none --no-checkout --depth 1 https://github.com/lxyeternal/pypi_malregistry.git data/malregistry/mr
  ```
- **Sparse Checkout Commands:**
  - `bash scripts/fetch_malregistry.sh --list [filter]`: Search and inspect available malware package names without fetching blobs.
  - `bash scripts/fetch_malregistry.sh <pkg1> <pkg2> ...`: Cone-mode sparse checkout of specific package directories.
  - `bash scripts/fetch_malregistry.sh --sample 5 --seed 1337`: Reproducible pseudo-random sampling.
- **Windows NTFS Compatibility:** The upstream repository contains a folder name with a trailing space (`user-agents-parser /`). On Windows, `git -C data/malregistry/mr config core.protectNTFS false` is applied to avoid checkout aborts.

### 4. Label Integration & Evaluation Harness
- **Reproducible Sampler (`bench/tools/sample_malregistry.py`):**
  - Generates `bench/labels_malregistry.yaml` conforming strictly to `schemas/bench_labels.schema.json`.
  - Sets `category: malregistry`, `label: malicious`, and `expected_verdict: MALICIOUS-EVIDENT`.
  - Ensures each extracted package directory contains a descriptive `README.md` for claim inspection.
- **Harness Integration (`eval/run_eval.py`):**
  - Evaluated via `python -m eval.run_eval --labels malregistry --runner fixture|live`.
  - Automatically discovered when running `--labels all`.
  - Aggregated under `external_malware` metrics alongside Datadog samples, ensuring synthetic planted toy recall remains strictly isolated.

## Verdict &times; Rule Coverage & ROC Threshold Sweep (C12)

Comprehensive visualization and sensitivity analysis combining detection rule coverage across verdicts with an empirical ROC threshold sweep using `trustlens/engine/weights.yaml` in read-only mode.

### 1. Verdict &times; Rule Coverage Heatmap (`eval/heatmap.py`)
- **Rule &times; Verdict Distribution Matrix:**
  Maps TrustLens detection rules (`canary_read_then_network`, `canary_in_outgoing_bytes`, `network_unclaimed`, `decoded_exec`, `env_differential`, `startup_hook`, `persistence`, `download_exec`, `capability_not_claimed`, `sandbox_probe`) against the four engine verdicts:
  - `MALICIOUS-EVIDENT` (Block: $\ge 2$ strong signals or canary in bytes)
  - `SUSPICIOUS` (Review: 1 strong signal or score $\ge \text{threshold}$)
  - `BENIGN-CONSISTENT` (Pass: observed behavior licensed by claims, coverage adequate)
  - `INCONCLUSIVE` (Abstain: thin coverage / dead package)
- **Package &times; Rule Activation Grid:**
  Visualizes individual package rule activations, ground-truth labels, finding scores, and final verdicts across all evaluated packages.

### 2. ROC-like Decision Threshold Sweep (`eval/threshold_sweep.py`)
- **Read-Only Invariant:**
  Scoring parameters and thresholds are read from `trustlens/engine/weights.yaml` in strict read-only mode. No scoring weights or thresholds in the engine are modified.
- **Empirical ROC Curve & AUC:**
  - Evaluates True Positive Rate (Recall) vs False Positive Rate (FPR) across 16 decision thresholds ($T \in [0.0, 1.0, 2.0, \dots, 15.0]$).
  - Calculates Area Under the ROC Curve (AUC) via trapezoidal numerical integration.
  - Inline SVG visualization in `reports/eval/heatmap.html` displays the empirical curve, random chance reference line, and callout badge for the nominal operating point.
- **Sensitivity Analysis (&plusmn;20%):**
  - Evaluates decision stability when `suspicious_threshold: 4.0` is perturbed by $\pm 20\%$:
    - Lower sensitivity bound: $T = 3.2$
    - Nominal operating point: $T = 4.0$
    - Upper sensitivity bound: $T = 4.8$
  - Tracks $\Delta \text{TPR}$ and $\Delta \text{FPR}$ to verify that the default operating point is robust and does not sit on an unstable decision boundary.
  - Logs any packages that transition verdicts across the $\pm 20\%$ window.

## Live Sandbox Invariants & Known Baseline Calibration Notes

### 1. Canary Environment & `ssh_helper` (`~/.ssh/config`)
- **Observed Behavior:** `ssh_helper` attempts to open and parse `~/.ssh/config` inside a `try/except` block with no `os.path.exists()` guard.
- **Canary World Finding:** In live sandbox runs, `ssh_helper`'s fingerprint remains empty because Dev A's sandbox canary provisioning generates `.ssh/id_rsa` and `.ssh/known_hosts`, but the canary world has no `~/.ssh/config`.
- **Architectural Decision:** We document this gap (ask Dev A to provision `~/.ssh/config` in `CANARY_DEFS` if canary coverage on SSH configs is desired). `ssh_helper` deliberately does **not** switch to reading `id_rsa`, as doing so would trigger `canary_access` alerts and violate the requirement that clean packages maintain a `BENIGN-CONSISTENT` verdict.

### 2. Pre-Dev-B Engine Attribution Noise (`cli_runner`, `hash_util`)
- **Observed Behavior:** On the pre-Dev-B engine, live dynamic scans mark clean packages `cli_runner` and `hash_util` as `SUSPICIOUS`.
- **Root Cause Analysis:** The sandbox baseline's inspection scripts execute utility pipelines (specifically `cut -c1` and `cut -c2-` during shell command execution). On the pre-Dev-B engine, these sandbox overhead processes are incorrectly attributed to the package under analysis rather than filtered as toolchain/runner baseline activity.
- **Ground-Truth Invariant:** In accordance with project integrity constraints, the expected verdict for both `cli_runner` and `hash_util` remains strictly `BENIGN-CONSISTENT` in `bench/labels.yaml`. We never relabel clean packages to SUSPICIOUS to match temporary engine calibration artifacts.
