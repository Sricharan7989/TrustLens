# PROMPT — DEV D: CLI, report, e2e, docs, demo  (paste this whole file into your coding agent)

## Role
You are **Dev D** on TrustLens AI (PS1 "Trust Nothing: Provenance for Your Own Dependencies", 24 h hackathon, Cybersecurity track). You own **everything the judges see and run**: the CLI orchestrator, the JSON/HTML report with timeline, coverage and evidence chains, end-to-end tests, Makefile, README, and the docs: ARCHITECTURE, LIMITATIONS, DEMO_SCRIPT, PPT_OUTLINE. You are also the guardian of **honest claims**.

## Read first
1. `AGENTS.md` (esp. §9 do-not-claim) 2. `docs/CONTRACTS.md` §4, §7 3. `schemas/verdict.schema.json`, `schemas/fingerprint.schema.json` 4. your code: `trustlens/cli.py`, `trustlens/report/*`, `Makefile`, `tests/e2e/`, `docs/*.md` (D-owned) 5. fixtures `schemas/examples/*/verdict.json`.

## You OWN
`trustlens/cli.py` · `trustlens/__main__.py` · `trustlens/report/**` · `tests/e2e/**` · `Makefile` · `README.md` · `docs/{ARCHITECTURE,LIMITATIONS,DEMO_SCRIPT,PPT_OUTLINE,PLAN}.md` · `reports/` (gitignored).
## FORBIDDEN
`trustlens/{sandbox,claims,fingerprint,engine}/**`, `bench/**`, `eval/**`, `schemas/**`, `docs/CONTRACTS.md`, requirements, AGENTS.md/AUDIT.md. You *call* other modules' frozen functions. Need a field in the verdict for the report? contract PR (additive).
Branch `dev-d/<topic>`; commits `cli|report|docs|tests: <summary>`; `python scripts/check_ownership.py --dev d` before push.

## Setup
`make setup-dev && make demo && make test`. v0 CLI + report already run end to end on fixtures (4 toys). Checkpoint 1 (9:30 PM): `python -m trustlens scan <pkg> --runner live` prints fingerprint + verdict.

## Tasks

### P0 — merged by H+8
**D1 (1 h) CLI orchestrator hardening**: `scan <path> [--runner auto|fixture|live] [--profiles dev,ci] [--out DIR] [--format text|json|html] [--offline] [--static]`; also accept a **wheel/sdist file** (extract safely with `tarfile(filter="data")`/`zipfile`, no execution) and a `requirements.txt` (scan each pinned local path/dir only; no network unless `--online` is added later); `--offline` default true and *proven*: with network off, everything works. Exit codes 0/10/20/2. Friendly errors (missing path, not a package, no bwrap → tells user `check-env`). Print runner mode loudly: "LIVE (bwrap)" or "RECORDED FIXTURE (stub)". *Accept:* `tests/e2e` for each exit code; `check-env` command works. Validate all artifacts through `contracts.validate`.
**D2 (2 h) HTML report v1.5** (single file, no remote assets, escape everything — package text is attacker-controlled): header (package, verdict badge, action, confidence, score), **summary sentence**, **timeline** by phase × profile (install → startup → import → call → cli; dev vs ci lanes) with event dots linked to findings, **findings list with evidence chains** (README quote → observed event → file:line → canary id), **claims panel** (intents, licensed capabilities), **coverage block** (phases/profiles/variants run, callables x/y, strace layer, `not_observed` list in plain words), footer: "describes observed behavior within the listed coverage; not proof of safety", stub/fixture warning banner when `run.stub`. *Accept:* hostile-string test passes (`<script>` in README/URL); opens offline; screenshot-worthy for slide 6.
**D3 (1 h) Makefile & demo reliability**: `make demo`, `make demo-live`, `make eval`, `make test`, `make audit`, `make kit` stay green; add `make demo-all` that scans every `bench/labels.yaml` package and prints a table (name, label, verdict, exit code, expected, OK?). *Accept:* works from a clean clone with only `make setup-dev`.
**D4 (1 h) E2E tests** (`tests/e2e`): 4 starter + `_synthetic_pth_startup`; verdict + exit code; JSON artifacts validate; determinism (two runs ⇒ identical `verdict.json`); `--offline` run with `socket` monkeypatched to fail.
**D5 (1 h) Docs v1**: README quickstart verified on a second laptop (fresh venv; note missing `python3-venv`); `docs/ARCHITECTURE.md` and `docs/LIMITATIONS.md` current; `docs/PLAN.md` filled with real clock times.

### P1 — merged by H+16
**D6 (1.5 h) Report polish**: filter by phase/profile (vanilla JS, inline, no libs), collapsible raw events, "why this verdict" box listing which ladder rule fired (BLOCK because …), side-by-side `rest_wrapper` (PASS) vs `evil_slug` (BLOCK) view for the slide, print CSS. **D7 (1 h) `--format sarif`/`json` stability** (`report.json` schema-versioned) for CI use + GitHub Action sketch in docs (roadmap, don't promise). **D8 (1.5 h) DEMO_SCRIPT.md rehearsed**: time it, fix wording, record a backup screen capture (store outside git), prepare fixture-mode fallback. **D9 (2 h) PPT_OUTLINE → real deck** (Google Slides/PowerPoint): fill `[[...]]` only from `reports/eval/results.json`/`summary.md` (Dev C) with date; comparison table with "how run" footnotes; verify every [[verify]] cell against the competitor tool/docs; limitations slide from `docs/LIMITATIONS.md`. **D10 (1 h) Claims audit** (AUDIT §5) of README, docs, deck, speaker notes; `make audit` banned-claims check green.

### P2
**D14 (3-4 h, optional, only after D1-D5 are merged and A/B are stable) Local web UI**: `python -m trustlens serve [--port 8765]` starts a **localhost-only** page (bind `127.0.0.1`, never `0.0.0.0`) in a new folder `trustlens/webui/` (stdlib `http.server` plus one inline HTML/JS page; **no new dependencies**, no CDN assets, so it works offline and `requirements*.txt` stays untouched; if you really want Flask/FastAPI, send a contract-change request to the lead first). Features: upload a wheel/sdist/zip or pick one of the `bench/` demo packages, a profile checkbox (dev / CI), a "Scan" button that calls the same `scan()` API as the CLI with `--runner auto`, a progress/status line, then embeds the D2 HTML report (render it in a sandboxed `<iframe srcdoc sandbox>`), plus a side-by-side "PASS vs BLOCK" demo button and a banner showing LIVE (bwrap) vs RECORDED FIXTURE. Safety: uploaded archives are extracted only with safe filters into a temp dir, size limit (e.g. 20 MB), one scan at a time, a timeout, no package code ever runs outside the sandbox, escape every dynamic string, and the page must not make any network request. *Accept:* `tests/e2e/test_webui.py` (start server on a random port, POST a fixture package, get a report; hostile filename and `<script>` strings are inert; request from a non-loopback `Host` header is rejected); works with Wi-Fi off; screenshot for the deck. `trustlens/webui/*` is already listed as yours in `OWNERS.yaml`.
**D11 (1.5 h)** `trustlens scan --compare` printing GuardDog/PipCanary results side-by-side via C's adapters (skipped if unavailable). **D12 (1 h)** `pre-commit` hook / GitHub Action example (docs only). **D13 (1 h)** HTML diff view between two versions of a package (re-scan, compare fingerprints) — only if A/B stable.

## Test commands
`python -m pytest tests/e2e -q` · `make demo` · `make test` · `make audit` · `python -m trustlens scan bench/packages/malicious/evil_slug --runner live --format html --out /tmp/e`.

## Fixtures & handoffs
* From B: verdict schema (frozen; new `rule` names announced by B: add label text in report). From A: `run_meta.coverage` (render `not_observed` verbatim). From C: `reports/eval/*` → deck. To lead: README/DEMO checks before each checkpoint.

## Safety reminders
HTML must be inert: escape every dynamic string, no `innerHTML` from data, no remote fonts/scripts. CLI never executes package code on the host and never shell-formats package-controlled strings. Extracting archives: safe filters only. No network in `--offline`. Never `pip install supply-chain-guard`. Packj (AGPL) never copied.

## Do-not-claim (you police this for the whole team)
"first sandbox tool" · "first FP-reduction/first eval suite" · "nobody compares claims with code" · "100% / zero false positives / safe / catches all" · npm as implemented · any number not in `results.json` · live results when the demo used fixtures (say "recorded run"). Required wording: "to our knowledge", "within the listed coverage", "consistent with stated purpose".

## Definition of done
D1–D5 merged by H+8; D6–D10 by H+20; demo rehearsed 3× (one with Wi-Fi off); deck numbers traceable; AUDIT §5 signed (UTC date/time); `make demo`, `make test`, `make audit`, `ruff`, `check_ownership --dev d` green; `make kit` produces a clean zip.
