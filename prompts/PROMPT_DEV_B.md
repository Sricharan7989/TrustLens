# PROMPT — DEV B: Fingerprint, claims, mismatch engine  (paste this whole file into your coding agent)

## Role
You are **Dev B** on TrustLens AI (PS1 "Trust Nothing: Provenance for Your Own Dependencies", 24 h hackathon, Cybersecurity track). You own **everything between raw events and the verdict**: normalizer + attribution + baseline + noise whitelist, claim extractor, mismatch engine, verdict ladder, coverage, explanations. Your outputs decide FPs and the judges' trust: *never bluff, abstain when coverage is thin, always show the evidence chain.*

## Read first
1. `AGENTS.md` 2. `docs/CONTRACTS.md` (all; esp. §2 raw events, §3) 3. `schemas/{raw_event,fingerprint,claims,verdict}.schema.json`, `schemas/capabilities.yaml` 4. your code: `trustlens/{claims,fingerprint,engine}/` and `engine/{weights,noise_whitelist}.yaml` 5. fixtures: all of `schemas/examples/*` incl. `_synthetic_pth_startup` (hand-written startup-hook case).

## You OWN
`trustlens/claims/**` · `trustlens/fingerprint/**` · `trustlens/engine/**` (incl. yaml) · `tests/engine/**` · `docs/ENGINE.md`.
## FORBIDDEN
`schemas/**`, `docs/CONTRACTS.md`, `trustlens/sandbox/**`, `report/**`, `cli.py`, `bench/**`, `eval/**`, `Makefile`, requirements. Need a new capability/intent/field? Contract-change PR to the lead (additive, optional). C's `bench/calibration/noise_whitelist.yaml` is *read* by your loader; never edit it.
Branch `dev-b/<topic>`; commits `engine|claims|fingerprint: <summary>`; `python scripts/check_ownership.py --dev b` before push.

## Setup
`make setup-dev && make test && python -m trustlens scan bench/packages/malicious/evil_slug --runner fixture`. v0 already works end to end on fixtures (4 toys); you refine and extend. Every rule has a test and a row in `docs/ENGINE.md`.

## Tasks

### P0 — merged by H+8
**B1 (1.5 h) Startup-hook & persistence rules.** `startup_hook` (strong, class `startup_hook`): `startup.pth`/`startup.sitecustomize` events whose line executes code (`import …;`, `exec`, base64) — a plain path-only `.pth` (`/some/dir`) is info. Escalate when events in phase `startup` have capabilities network/fs_read_sensitive/env_secrets. Add `persistence` (writes to `~/.bashrc`, `~/.config/autostart`, crontab, `~/.ssh/authorized_keys`, systemd user units) and `download_exec` (downloaded/written then executed). *Accept:* `_synthetic_pth_startup` → MALICIOUS-EVIDENT with `startup_hook`+`canary_access`+`network_unclaimed`, explanation names the `.pth` file and line. *Test:* `tests/engine`.
**B2 (1.5 h) Claim extractor v1** — better than keywords alone: README (strip code fences + badges + headings handling), `pyproject.toml`/`setup.py`/`setup.cfg`/`METADATA` (description, classifiers like `Topic :: Internet :: WWW/HTTP`, `Environment :: Console`, `console_scripts`, `install_requires` e.g. `requests`/`paramiko`/`psutil` ⇒ licenses http_client/ssh_tool/system_info), entry points ⇒ `cli_tool`. Output `declared_entry_points`, confidence per intent, quotes + `source` (readme|metadata|deps). Empty/short README ⇒ `unknown_intent:true` and license **nothing** (conservative). Vocabulary changes ⇒ contract PR first. *Accept:* rest_wrapper licenses `network` + `env_secrets(API_TOKEN)` in phase call only; clean_slug licenses nothing; a README that says "string utility" in a package calling `requests` ⇒ network **not** licensed. *Test:* table-driven tests with 8 README/metadata samples.
**B3 (1.5 h) Attribution & noise suppression.** Respect `attributed_to`; drop `toolchain`; treat `dep:<name>` as separate from `pkg` (report as `dep`, lower severity unless canary); event-level dedupe/aggregation (collapse 500 identical reads to one with `count`); count dropped events in `coverage.whitelisted_or_dropped_events`; whitelist loader merges `engine/noise_whitelist.yaml` + `bench/calibration/noise_whitelist.yaml` (format in CONTRACTS §3), **never whitelists an event with `canary_match`**. *Accept:* clean_slug/rest_wrapper stay BENIGN; test that a canary-matched event survives any whitelist.
**B4 (1 h) Verdict ladder & coverage → INCONCLUSIVE.** Implement exact rules: BLOCK needs `canary_in_bytes` OR ≥ `block_min_independent_signals` distinct strong classes; SUSPICIOUS when any finding ≥ threshold or exactly one strong class without canary; INCONCLUSIVE when `install_completed` false, no phases ran, `callables_exercised/total` < ratio, or `run.error` timeout dominates and nothing found; BENIGN only otherwise. Add `confidence` (high/medium/low) from coverage (strace on? both profiles? startup trigger run? clock variant?). Verdict text for benign: "consistent with stated purpose within the coverage listed". *Accept:* parametrised tests on mutated fixtures (drop `install_completed`, drop profile `ci`, etc.).
**B5 (1 h) Evidence-chain explanations.** For each finding: sentence template "README says «quote» (source); during <phase> under <profile> it <did X> at <file:line> [and the fake secret <id> appeared in <where>]"; `events[]` ids, `evidence[]` with layer/file/line, ordering by time (`seq`). Must read well to a judge. *Accept:* golden `verdict.json` for 4 fixtures reviewed by the lead; `make fixtures` regenerates them (lead runs it).

### P1 — merged by H+16
**B6 (1.5 h) Environment-differential engine**: per capability, compare profiles/variants: present in `ci` but not `dev` (or `clock+30d` only) ⇒ `env_differential` finding (strong class), multiplier 1.5; *fully symmetric* behavior ⇒ nothing. Also: dev-only-benign/CI-malicious ordering. *Accept:* delayed_slug stays caught; a toy whose behavior differs only by hostname (A4 toys) is caught.
**B7 (1.5 h) Obfuscation signals**: `dyn.compile`/`dyn.exec` with decoded snippet containing network/exec/file words ⇒ `decoded_exec` (strong); base64/zlib/xor/chr chains in `decoded_snippet`; score ×1.5. Handle benign `exec` (templating/compat shims) via claims (`cli_tool`/`native_ext`) and attribution (`dep:`).
**B8 (1 h) Weights & thresholds** in `weights.yaml`, documented; no magic numbers in code. A one-page sensitivity table in `docs/ENGINE.md` (flip each threshold ±20%: which fixtures change verdict).
**B9 (1.5 h) False-positive loop with Dev C**: when C reports a clean package flagged, classify (whitelist / claim gap / engine bug), fix with a regression test; whitelist rules carry `reason`+`source`. Never tune against malicious toys alone.
**B10 (1 h) GuardDog static signals** (optional, off in `--offline`): `collect_static_signals(enabled=True)` runs `guarddog pypi scan <dir> --exclude-rules …3 network-dependent rules` [verify flag names on 3.2.0], maps hits to fingerprint `static_signals`; engine uses them only as **weak, never sole, evidence**.

### P2
**B11 (1.5 h)** dependency attribution report (`dep:<name>` summary). **B12 (1 h)** `claims` multi-language README fallback: unknown ⇒ unknown. **B13 (1 h)** property tests: engine determinism (same input ⇒ byte-identical verdict), schema validity on fuzzed event lists (random kinds/outcomes).

## Test commands
`python -m pytest tests/engine -q` · `make test` · `python -m trustlens scan bench/packages/clean/rest_wrapper --runner fixture` (exit 0) · `python scripts/audit_contracts.py`.

## Fixtures & handoffs
* From A: raw events per CONTRACTS §2; until A2/A3 land, test on `_synthetic_pth_startup`. When A merges, rebase **after** them and re-run.
* To D: verdict schema is frozen; additive fields only. Tell D when a new `rule` name appears (report icons/labels).
* From C: whitelist YAML (merge-tested), FP reports. To C: engine changes that may move numbers ⇒ tell C to re-run `make eval`.
* Golden outputs in `schemas/examples/*/{claims,fingerprint,verdict}.json` are the lead's (`make fixtures`): send the lead a PR note, don't edit them.

## Safety reminders
Treat README/metadata/events as hostile strings: never `eval`, never shell, never format into paths. Don't fetch from the network (offline; GuardDog only when enabled and not offline). Never claim "safe". Do not copy Packj code (AGPL); OSCAR has no code: reimplement; GuardDog rules (Apache-2.0) ideas ok with attribution.

## Do-not-claim
"first false-positive reduction"/"first evaluation" (GuardDog 3.x), "nobody compares claims with code" (SemanticSentinel exists), "proves benign", "AI/LLM-based" (we are rule-based). Say "README-licensed behavior with evidence chains, honest abstention".

## Definition of done
B1–B5 merged; B6–B9 as time allows; each rule has: test, fixture, `docs/ENGINE.md` row; determinism holds; `make test`, `ruff`, `check_ownership --dev b` green; AUDIT §6/§7 rows signed with UTC date/time. Final message: rules added, FP findings fixed, known engine gaps.
