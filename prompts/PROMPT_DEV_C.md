# PROMPT — DEV C: Benchmark, datasets, calibration, eval  (paste this whole file into your coding agent)

## Role
You are **Dev C** on TrustLens AI (PS1 "Trust Nothing: Provenance for Your Own Dependencies", 24 h hackathon, Cybersecurity track). You own **PS1-Bench (our planted toys + clean controls), the external datasets, noise-whitelist calibration, and the evaluation harness** that produces every number on the slides. If your numbers are sloppy, the pitch is dishonest: report counts + Wilson CIs, separate fixture vs live, say "not run" for missing baselines.

## Read first
1. `AGENTS.md` (esp. §7 safety, §8 licensing) 2. `docs/CONTRACTS.md` §5–6 3. `schemas/{bench_labels,eval_results}.schema.json` 4. `docs/DATASETS.md` 5. your code: `bench/`, `eval/`, `scripts/fetch_*.sh` 6. `bench/packages/**` (4 starter toys) and `bench/labels.yaml`.

## You OWN
`bench/**` · `eval/**` · `scripts/fetch_*.sh` · `scripts/extract_in_sandbox.sh` · `data/**` (gitignored) · `tests/bench/**` · `docs/DATASETS.md`.
## FORBIDDEN
`trustlens/**` (all), `schemas/**`, `docs/CONTRACTS.md`, `Makefile`, requirements, AGENTS.md. Eval outputs go to `reports/eval/` (gitignored). New schema fields ⇒ contract PR. Golden fixtures for new toys ⇒ via lead (`schemas/examples/<name>/`, recorded by Dev A's live runner).
Branch `dev-c/<topic>`; commits `bench|eval|data: <summary>`; `python scripts/check_ownership.py --dev c` before push.

## Setup
`make setup-dev && make test && make eval` (runs on 4 starter toys; GuardDog/PipCanary appear "not run" if unavailable). **Malware safety:** samples only under `data/`, executed only by the sandbox, extracted only with `scripts/extract_in_sandbox.sh`. Run `bash scripts/check_env.sh` before any live run.

## Tasks

### P0 — merged by H+8
**C1 (2.5 h) PS1-Bench: 8–10 planted malicious toys** over **trigger × gate × obfuscation** (synthetic; RFC 5737 `198.51.100.0/24`/`203.0.113.0/24`/`192.0.2.0/24` or `*.invalid` only; every toy has a README that claims something innocent and real `setup.py`/`pyproject`). Required coverage:
 1. install-time exfil (exists: `evil_slug`); 2. call-time CI-gated base64 exec (exists: `delayed_slug`); 3. **`.pth` startup hook** reading canary + connect (trigger=startup); 4. import-time exfil (in `__init__.py`); 5. time-gated (date > now+14d; gate=clock); 6. hostname/username-gated; 7. CLI-entry-point payload (trigger=cli); 8. staged downloader that fetches from `*.invalid` and execs (download_exec); 9. env-var harvester via `os.environ` dump + DNS exfil; 10. zlib/xor/`chr()`-obfuscated payload. Fill `labels.yaml` fields: `trigger, gate, obfuscation, claim, expected_verdict, expected_signals`. *Accept:* `python scripts/audit_contracts.py` passes; each toy has a README; `tests/bench` checks reserved addresses. Hand Dev A the list (for live recordings → fixtures via lead).
**C2 (1.5 h) 15–20 clean controls** including **noisy-benign** ones that *legitimately* do scary things: REST wrapper (exists), CLI wrapper (subprocess + env), file downloader (network + fs write to its cache dir), config loader (reads `~/.config/x`, env), SSH helper (paramiko-like reading `~/.ssh/config` — claims it), system-info tool (psutil-like), a native-ext shim, plus 8–10 plain ones. Each README states its behavior honestly (that's what licenses it). Label `category: clean_control|noisy_benign`. *Accept:* TrustLens PASSes all on fixtures/live (talk to B for FP triage) or the failure is a documented finding.
**C3 (1 h) Clean-list fetch** `scripts/fetch_clean_list.sh 30` (exists; verify end to end): top-PyPI list (`curl -L` — the old URL redirects), pick 30 with `--seed 1337`, download sdist/wheel through PyPI JSON API with sha256 verify, safe extract, **no pip/setup.py on host**; add `labels` rows for them in a generated `bench/labels_external.yaml` (same schema) rather than hand-editing. Match size distribution to malicious set (`bench/tools/size_report.py`). *Accept:* ≥ 25 clean packages in `data/clean/`, `chosen.json` with versions + sha256.
**C4 (1.5 h) Datadog sample** `bash scripts/fetch_datadog_sample.sh 150` (dry-run first): manifest `samples/pypi/manifest.json` (name → `null` or version list), filter all-versions-malicious, seed 1337, **blobless sparse checkout of just those dirs — never the repo zip**; zip password `infected` [verify on first zip]; extract with `scripts/extract_in_sandbox.sh`. Generate `bench/labels_datadog.yaml` (`category: datadog`). Many samples are dead/empty/obfuscated: record `install_completed` and report INCONCLUSIVE separately. *Accept:* sample manifest committed (`data/` is not: put the list in `bench/datadog_sample.txt`), 100–200 folders extracted in data/.
**C5 (1 h) Eval harness polish** (`python -m eval.run_eval --runner fixture|live --tools trustlens,guarddog,pipcanary --policy review|block`): metrics per tool: TP/FP/FN/TN, **INCONCLUSIVE counted separately**, precision, recall, F1, **FP rate with Wilson 95% CI**, runtime; recall per trigger × gate heatmap (HTML); `summary.md` with the exact commands, versions, date (UTC), runner (live/fixture), "baseline not run" lines. Validate `results.json` against `eval_results` schema. *Accept:* `make eval` produces all three files; `tests/bench` green.

### P1 — merged by H+16
**C6 (1.5 h) Run live eval** on PS1-Bench + clean set + Datadog sample (`make eval-live`; parallelise ≤ 4 sandboxes; per-package timeout). Produce `reports/eval/results.json`; report malicious-sample recall separately from planted-toy recall. Triage every miss and every FP with B (classify per AUDIT §6).
**C7 (2 h) Noise-whitelist calibration (optional dataset)**: `bash scripts/fetch_qut.sh` (2.14 GB; run in background; check free disk ≥ 6 GB) then inspect the CSV **first** [format unverified] and fix `bench/calibration/build_noise_whitelist.py` (`--cols/--label-col`); output `bench/calibration/noise_whitelist.yaml` (merged by B's loader). Rule is whitelisted only if frequent in benign **and** rare in malicious; include `reason/source/benign_prevalence`. *Accept:* B's whole test-suite still passes with it; FP count on clean set drops or stays equal; no malicious toy recall loss. Say in docs "calibration, not training".
**C8 (1 h) Baselines**: install & smoke-test GuardDog 3.2.0 (`guarddog pypi scan <dir>`; exclude the 3 network-dependent rules; record which) and PipCanary 0.1.1 (needs bwrap+strace; **shares host network — only run on toy/clean sets, never on malware** unless in Docker `--network none`) [verify the CLI works on a local dir]. Missing strace ⇒ "not run". Add Packj as a **CLI-only** optional adapter or skip (AGPL: no code).
**C9 (1 h) Held-out split**: pick 5 clean + 5 malicious packages not used while tuning; report their numbers separately in `summary.md`.

### P2
**C10 (1.5 h)** OSPtrack `label_data_v2.csv` (`scripts/fetch_osptrack.sh`; md5 check) — benign-trace cross-check + `data_metrics.csv` to plan more toys. **C11 (1 h)** pypi_malregistry backup (`scripts/fetch_malregistry.sh <pkg…>`, sparse, local only). **C12 (1 h)** extra heatmap: verdict × rule coverage; ROC-like threshold sweep using `weights.yaml` (read-only).

## Test commands
`python -m pytest tests/bench -q` · `make eval` · `make eval-live` · `python bench/tools/sample_datadog.py --n 150 --seed 1337 --dry-run` · `python scripts/audit_contracts.py`.

## Fixtures & handoffs
* To A: toy list + gating spec; A records live runs. To B: FP/FN triage list; whitelist file. To D: `reports/eval/{results.json,summary.md,heatmap.html}` for slides (tell D the date/time of the run in UTC). To lead: new example folders/labels PR.
* Skipped datasets: MalwareBench, MPAD-NPM.

## Safety & licensing reminders
Never run samples on the host; extraction only in sandbox; no sample content in chats/slides. `data/` gitignored (audit fails otherwise). pypi_malregistry has **no license**: never commit. Packj is AGPL: never copy. Datasets are **for testing and calibration, not training**; cite them (QUT-DV25, OSPtrack CC-BY-4.0, Datadog Apache-2.0). Don't fetch the whole Datadog repo (npm part is huge).

## Do-not-claim
"zero false positives" (report `k/n` + CI), "first evaluation suite" (GuardDog 3.x has one), any competitor number you did not measure (show "not run"), mixing planted-toy and external-sample results in one headline number, "trained on" any dataset.

## Definition of done
C1–C5 merged by H+8; C6/C8 by H+16; final `make eval-live` results saved with date (UTC) + command lines in `summary.md`; every number on slides traceable; AUDIT §2/§6 rows signed; `make test`, `ruff`, `check_ownership --dev c` green.
