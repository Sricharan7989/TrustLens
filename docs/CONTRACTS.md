# CONTRACTS (FROZEN as of hour 0). Owner: **Lead (the 5th teammate)**

This file + `schemas/*.json` + `schemas/capabilities.yaml` are the only things the four dev folders share.
**Never change a contract by editing code in your own folder.** See section 9 for the change process.
Machine check: `python scripts/audit_contracts.py` (also in `make test` and `make audit`).

Version: `schema_version: "1.0"` in every JSON artifact. Example artifacts: `schemas/examples/<package>/`.

## 0. Data flow (who produces what)

```
package dir ──A──▶ raw_events.jsonl + run_meta.json ──B──▶ claims.json + fingerprint.json ──B──▶ verdict.json ──D──▶ report.html/json + exit code
                                                                  ▲                                  ▲
                                          bench/packages (C) ─────┴── labels.yaml (C) ──▶ eval (C) ──┘ (C scores verdict.json vs labels)
```

| # | Artifact | Schema | Producer | Consumer |
|---|---|---|---|---|
| 1 | `raw_events.jsonl` (1 JSON per line) | `schemas/raw_event.schema.json` | A | B |
| 2 | `run_meta.json` | `schemas/run_meta.schema.json` | A | B, D |
| 3 | `claims.json` | `schemas/claims.schema.json` | B (`claims/`) | B (engine), D |
| 4 | `fingerprint.json` | `schemas/fingerprint.schema.json` | B (`fingerprint/`) | B (engine), D, C |
| 5 | `verdict.json` | `schemas/verdict.schema.json` | B (`engine/`) | D, C |
| 6 | `bench/labels.yaml` | `schemas/bench_labels.schema.json` | C | C, tests |
| 7 | `reports/eval/results.json` | `schemas/eval_results.schema.json` | C | D (slides/report) |
| 8 | capability + intent vocabulary | `schemas/capabilities.yaml` | Lead | A, B, C, D |

## 1. Vocabulary (`schemas/capabilities.yaml`, read it; this is the summary)

* **phases**: `install`, `startup` (fresh interpreter, no import), `import`, `call`, `cli`.
* **profiles**: `dev` (laptop camouflage), `ci` (CI vars set). **variants**: `default`, `clock+30d`.
* **capabilities (12)** with default severity: `network`4, `fs_read_sensitive`6, `fs_write_outside_pkg`5, `env_secrets`5, `subprocess`3, `dynamic_exec`6, `persistence`8, `install_hook`3, `startup_hook`8, `native_code`2, `sandbox_probe`3, `download_exec`9.
* **intents (8)** → licensed capabilities: `string_util`(none), `http_client`, `cli_tool`, `downloader`, `config_loader`, `ssh_tool`, `system_info`, `native_ext`. Adding a capability/intent = contract change.
* **outcomes**: `attempted`, `succeeded`, `blocked`, `unknown`. In the sandbox network is always blocked, so a connect is `blocked` — the *attempt* is the evidence.

## 2. Dev A → B: `run_package` + raw events (FROZEN)

```python
# trustlens/sandbox/runner.py  (A implements, D calls)
run_package(pkg_path: str, out_dir: str, *, profiles=("dev","ci"), triggers=DEFAULT_TRIGGERS,
            offline: bool = True, timeout_s: int = 120, runner: str = "auto") -> RunResult
# RunResult = {"raw_events_path": str, "run_meta_path": str, "run_meta": dict}
# runner: "auto" (= live if check_env()["bwrap_ok"] else fixture) | "live" | "fixture" | "docker" (A stretch)
# triggers: subset of ("install","fresh_startup","import_all","call_all","cli")
```
Rules: pure function of `pkg_path`; writes only under `out_dir`; **never executes package code on the host**; never raises for package misbehaviour (timeouts/crashes become `run.error` events + coverage flags); raises only for bad arguments.

**Raw event** (one JSON per line; schema is authoritative) required keys: `seq, phase, trigger, profile, variant, kind, detail, outcome, attributed_to`; optional `t, canary_match[], evidence{layer,file,line,…}`.

| kind | `detail` keys | notes |
|---|---|---|
| `file.read` / `file.write` / `file.new` | `path` (+`mode`) | paths under fake HOME are `/w/home/...`; B normalises to `~/` |
| `env.read` | `name` | A wraps `os.environ` (CPython emits no audit event for env reads) |
| `net.dns` / `net.connect` / `net.send` / `net.http` | `host` / `dest` / `dest,data_head` / `method,url,data_head` | `canary_match` lists canary ids found in url/bytes → "canary-in-bytes" |
| `proc.spawn` | `argv,via` | |
| `dyn.exec` / `dyn.compile` | `co_filename,co_name` / `code_sha256,decoded_snippet,source_kind` | decoded text is evidence for obfuscation |
| `install.hook` | `file` (+`cmd`) | setup.py cmdclass / build hook (A P1) |
| `startup.pth` / `startup.sitecustomize` | `file,line_text` | from real-install site-packages diff (**A P0**) |
| `native.load` | `path` | native code is invisible without strace layer → coverage |
| `run.error` | `where,message` | timeouts, install failures: B turns these into coverage, never into "clean" |

`attributed_to`: `pkg` | `toolchain` (pip/setuptools/wheel/our harness) | `dep:<name>`. **B drops `toolchain`, A must not guess: when unsure use `pkg`** (over-reporting is fixable in B's whitelist; under-reporting is invisible).
`evidence`: `{layer: "audit"|"envwrap"|"fs_diff"|"strace", file, line}` for evidence chains in the report.

**run_meta.json** (`schemas/run_meta.schema.json`): `run{sandbox,network,canaries,phases,profiles,variants,started_at,duration_s,stub,tool_versions}`, `coverage{phases_run,profiles_run,variants_run,triggers_run,install_completed,install_note,network,callables_total,callables_exercised,native_skipped,strace_layer,not_observed[]}`, `canaries[]` (ids + where; **never the token text of anything real**). `not_observed` is an honest list of what this run could NOT see; the engine converts it to INCONCLUSIVE/coverage text. Fixture replays set `run.stub=true, run.sandbox="fixture"`.

**Canary world** (A builds, ids are contract; source of truth `CANARY_DEFS` in `trustlens/sandbox/live_probe.py`): files `ssh_key` (`~/.ssh/id_rsa`), `aws_creds` (`~/.aws/credentials`), `npmrc` (`~/.npmrc`), `gcloud_creds` (`~/.config/gcloud/application_default_credentials.json`), `docker_config` (`~/.docker/config.json`); env `aws_secret_env` (`AWS_SECRET_ACCESS_KEY`), `github_token_env` (`GITHUB_TOKEN`). Each token is unique per run (`TLCANARY…`). A `canary_match` is set when a read touches the file or bytes/URL contain the token.

## 3. Dev B: claims, fingerprint, verdict (FROZEN signatures)

```python
# trustlens/claims/extract.py
extract_claims(pkg_path: str) -> dict           # validates against claims.schema.json
read_package_info(pkg_path: str) -> dict        # name, version, sha256, entry points, readme text
# trustlens/fingerprint/normalize.py
build_fingerprint(raw_events_path: str, run_meta: dict, package: dict, static_signals: list|None = None, whitelist: list|None = None) -> dict
# trustlens/fingerprint/static_signals.py
collect_static_signals(pkg_path: str, enabled: bool = False) -> list[dict]   # optional GuardDog wrapper; never on by default; never when --offline
# trustlens/engine/evaluate.py
evaluate(fingerprint: dict, claims: dict) -> dict                            # validates against verdict.schema.json
```
* **Normalised event** = raw event + `id` (`ev<N>`), `capability`, `canary_hit`, `canary_ids`. `fingerprint.capability_summary[cap] = {phases, profiles, conditional, count, canary_hit}`; `conditional=true` when the capability appears in only some profiles/variants (env-differential).
* **Verdict ladder** (`verdict` / `action`): `MALICIOUS-EVIDENT`/`BLOCK` · `SUSPICIOUS`/`REVIEW` · `INCONCLUSIVE`/`REVIEW` · `BENIGN-CONSISTENT`/`PASS`.
  * BLOCK needs **canary-in-bytes OR ≥ 2 independent strong signal classes** (`strong_signal_classes` in `engine/weights.yaml`). Never block on one weak class.
  * INCONCLUSIVE when coverage is too thin (install failed, callables_exercised/total < `min_callable_ratio_for_benign`, no phases ran). **Never print PASS on a package that did not run.**
  * `BENIGN-CONSISTENT` text must say "consistent with stated purpose within the coverage listed", never "safe".
* **Finding**: `{id:"f<N>", rule, signal_class, severity, score, claim{status: claimed|not_claimed|unknown_intent, quote, source}, events[ev ids], evidence[], explanation}`. Every finding has ≥1 event id and a human sentence ("README says X; code did Y at file:line in phase P under profile Q").
* **Rules shipped in v0** (B extends; rule name = contract for D's report and C's heatmap): `canary_read_then_network`, `canary_in_outgoing_bytes`, `network_unclaimed`, `decoded_exec`, `env_differential`, `startup_hook`, `persistence`, `download_exec`, `capability_not_claimed`, `sandbox_probe`.
* **Noise whitelist** rules (`engine/noise_whitelist.yaml` + C's `bench/calibration/noise_whitelist.yaml`, merged by B's loader): `{capability, path_glob|host_glob|env_glob, reason, source, benign_prevalence?}`. Whitelisted events are counted in `coverage.whitelisted_or_dropped_events`, never silently lost.

## 4. Dev D: CLI + report (FROZEN)

```
python -m trustlens scan <pkg_dir> [--runner auto|fixture|live] [--profiles dev,ci] [--out DIR] [--format text|json|html] [--offline] [--static]
python -m trustlens check-env
exit codes: 0 PASS · 10 REVIEW (SUSPICIOUS or INCONCLUSIVE) · 20 BLOCK (MALICIOUS-EVIDENT) · 2 usage/internal error
```
`scan` writes into `--out` (default `reports/<name>/`): `raw_events.jsonl run_meta.json claims.json fingerprint.json verdict.json report.json report.html`. In every scan, D validates each artifact with `trustlens.contracts.validate` (turn off only with `check_contracts=False`). `report.html` is a single self-contained file: no remote assets/scripts, all dynamic strings HTML-escaped (package READMEs and URLs are attacker-controlled).
Python API for C's eval (frozen): `from trustlens.cli import scan; scan(pkg_path, out_dir, *, runner="auto", profiles=("dev","ci"), offline=True, static=False, check_contracts=True) -> {"verdict": dict, "fingerprint": dict, "claims": dict, "out_dir": str}`.

## 5. Dev C: bench + eval (FROZEN)

* `bench/labels.yaml`: `version`, `packages[]: {id, path, label: malicious|clean, category: planted|clean_control|noisy_benign|datadog|real_malware, trigger, gate, obfuscation, expected_verdict, claim, expected_signals[], notes, known_issue?}` (schema `bench_labels`). `known_issue` (optional, additive) records why the current engine misses `expected_verdict`; the label stays the ground truth, `scripts/audit_contracts.py` prints the package as KNOWN instead of failing, and the eval still counts it. Package folders contain a `README.md` (claims source) and real source; **planted toys are synthetic and use only RFC 5737 addresses (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24) or `*.invalid`**.
* Trigger values: `install|startup|import|call|cli`. Gate values: `none|ci|clock|env|hostname|delay|random`. Obfuscation: `none|base64|xor|chr|zlib|split-string`.
* `python -m eval.run_eval --runner fixture|live --tools trustlens,guarddog,pipcanary --policy review|block [--out DIR]` writes `results.json` (schema `eval_results`), `heatmap.html`, `summary.md`. Baseline adapters return `{available, flagged: bool|None, rules, runtime_s, error}`; unavailable ⇒ `flagged: null` and the tool is shown as "not run", **never as 0 detections**.
* Metrics always report counts + Wilson 95% CI for FP rate (`eval/metrics.py`); `0/15` is shown as "0/15 (95% CI 0–20%)", never "0% FP".

## 6. Fixtures / stubs rule

`schemas/examples/<package-dir-name>/{raw_events.jsonl, run_meta.json, claims.json, fingerprint.json, verdict.json}` are the shared golden files. `raw_events.jsonl`+`run_meta.json` of the 4 starter toys are real recorded bwrap runs; `_synthetic_pth_startup/` is **hand-written** (startup `.pth` case) and says so. The 12 sandbox test toys recorded under `tests/sandbox/recorded/` (`broken_install`, `call_matrix`, `canary_shapes`, `cli_toy`, `clock_gate`, `env_patterns`, `github_gate`, `hostname_gate`, `native_open`, `probe_toy`, `pth_toy`, `sink_dropper`) are copied here as raw-event golden files only; they are not PS1-Bench packages, so `make fixtures` derives nothing for them. The fixture runner replays by directory name. Regenerate derived JSON with `make fixtures` (lead). New bench packages: A (or C with A's runner) records `raw_events.jsonl`+`run_meta.json` into `schemas/examples/<name>/` via a lead-reviewed PR, because it is a shared folder.

## 7. Cross-cutting rules every contract implies

* No network in product code unless behind a non-offline flag; `--offline` must work end to end. No LLM in the verdict path.
* All timestamps UTC ISO-8601 in artifacts; in docs for humans say which zone.
* Deterministic output: same input + same fixtures ⇒ byte-identical `verdict.json` (sort keys/lists; no wall-clock in verdicts).
* Everything attacker-controlled (README text, URLs, file names, decoded snippets) is data: escape on output, never `eval`/format into shell.

## 8. Handoff checklist (A→B, B→D, C→D)

1. Producer commits golden example(s) in `schemas/examples/`; `make test` green. 2. Producer posts the branch + one-line "contract unchanged" or "contract change #N" in the team chat. 3. Consumer rebases on `main` **after** the producer merged, never on the producer's branch.

## 9. Contract-change process (only way to touch shared files)

1. Open a PR **only** touching `docs/CONTRACTS.md`, `schemas/**`, `trustlens/contracts.py`, and example files: title `contract: <what> (#N)`; body: reason, who must adapt (A/B/C/D), migration. 2. Lead approves within 15 minutes or says no. Prefer **additive, optional** fields (never rename/remove). 3. Lead merges, runs `make fixtures && make test`, announces. 4. Affected devs rebase and adapt. Bump `schema_version` minor (`1.1`) only for additive changes; a breaking change needs the whole team's OK.

Change log: `#0` initial freeze.
