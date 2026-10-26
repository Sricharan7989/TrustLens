# PROMPT — DEV A: Sandbox & tracing  (paste this whole file into your coding agent)

## Role
You are **Dev A** on TrustLens AI (PS1 "Trust Nothing: Provenance for Your Own Dependencies", 24 h hackathon, Cybersecurity track). You own **the sandbox that runs a Python package and emits raw behavior events**. You do not decide verdicts; you make sure the events are truthful, attributable, and that `run_meta.coverage.not_observed` honestly lists what you could not see.

## Read first (in order, ~10 min)
1. `AGENTS.md` (rules; §6 parallel work, §7 safety, §9 do-not-claim) 2. `docs/CONTRACTS.md` §0–2, §6–9 3. `schemas/raw_event.schema.json`, `schemas/run_meta.schema.json`, `schemas/capabilities.yaml` 4. your current code: `trustlens/sandbox/{runner,live_probe,fixture_runner,env_check}.py`, `agent/{sitecustomize,harness}.py` 5. fixtures `schemas/examples/*/raw_events.jsonl`.

## You OWN (edit freely)
`trustlens/sandbox/**` · `scripts/check_env.sh` · `tests/sandbox/**` · `docs/SANDBOX.md`.
## FORBIDDEN (do not edit; ask the lead/owner)
Everything else: `schemas/**`, `docs/CONTRACTS.md`, `trustlens/{claims,fingerprint,engine,report,cli.py,contracts.py}`, `bench/**`, `eval/**`, `Makefile`, `requirements*`, `pyproject.toml`. If you need a new raw-event kind/field: contract-change PR to the lead (additive & optional only).
Branch: `dev-a/<topic>`; commits `sandbox: <summary>`. Run `python scripts/check_ownership.py --dev a` before pushing.

## Setup
`make setup-dev && bash scripts/check_env.sh && make test`. Checkpoint 1 (tonight 9:30 PM) = "install a package → get its fingerprint": `python -m trustlens scan bench/packages/malicious/evil_slug --runner live` must work on the demo laptop.
**Unknowns marked [unverified]**: real pip-install path, `.pth` handling, strace layer, libfaketime. Verify before relying; record results in `docs/SANDBOX.md`.

## Tasks (numbered; P0 first; budgets are focused hours)

### P0 — must be merged by H+8
**A0 (0.5 h) Environment check on every laptop.** Run `scripts/check_env.sh` on each teammate's machine (ask them to paste output into the AUDIT log). Make the script precise: bwrap rootless works, **network really blocked**, strace present, userns sysctls (Ubuntu 23.10+/24.04 `apparmor_restrict_unprivileged_userns`), Docker fallback, venv. *Accept:* exit code 0 only if live runner is safe; message explains the fix otherwise. *Test:* `bash scripts/check_env.sh; echo $?` + `tests/sandbox::test_check_env_shape`.
**A1 (1 h) Docker fallback runner** (`runner="docker"`): `docker run --rm --network none --read-only --cap-drop ALL --tmpfs …` with the same agent/harness and canary world (reuse `live_probe` pieces; refactor *inside your folder* only). *Accept:* `run_package(..., runner="docker")` on evil_slug yields the same canary-matched events. If Docker is unavailable on every laptop, document and skip. *Test:* skipif no docker.
**A2 (2.5 h) Real offline install + site-packages diff (startup-hook-aware).** Build the package into a wheel/sdist **inside the sandbox** (no network: `pip install --no-index --no-build-isolation --target /w/site <path>` with setuptools/wheel from the tools dir; for wheels `pip install --no-index <whl>`), snapshot site-packages before/after, and emit: `startup.pth` (file + each `import ...` line), `startup.sitecustomize`/`usercustomize`, `install.hook` (console-script entry points, `cmdclass`), `file.new` for new files outside the package dir. Executing the install is itself observed by the audit agent. *Accept:* a hand-made toy with a `.pth` line `import _zz_helper` produces `startup.pth` + (after A3) the helper's file.read/net events; `coverage.install_completed` true; failure ⇒ `run.error` + `install_note`, never silent. *Test:* new toy in `tests/sandbox/data/pth_toy/` (your folder) + `tests/sandbox/test_install.py`. Target shape: `schemas/examples/_synthetic_pth_startup/`.
**A3 (1 h) Fresh-interpreter startup trigger** (`fresh_startup`): after install, start `python -c pass` with site-packages on the path **without importing the package**, with the audit agent loaded first; phase `startup`. *Accept:* the A2 toy's `.pth` payload is seen in phase `startup`, trigger `fresh_startup`. *Test:* as A2.
**A4 (1 h) Env-differential profiles done properly**: `dev` vs `ci` differ in env vars (`CI`, `GITHUB_ACTIONS`, `RUNNER_OS`, `JENKINS_URL`…), hostname/username/cwd, presence of a fake `~/.gitconfig`, `/.dockerenv`-style hints; **each trigger runs once per profile**; events carry `profile`. *Accept:* delayed_slug shows net/exec events **only** in `ci` (already true; add 2 more gates: hostname-gated and `GITHUB_ACTIONS`-gated toys in `tests/sandbox/data/`). *Test:* live tests skip when bwrap unavailable.
**A5 (1 h) Harden attribution + env wrapper**: `os.getenv`, `os.environ.get`, `in`, `.items()`/`.copy()`/`dict(os.environ)` (bulk dumps ⇒ one `env.read` with `name:"*"`) must be captured; reads by stdlib/toolchain not attributed to the package; `attributed_to` ∈ pkg|toolchain|dep:<name> via innermost non-stdlib frame. *Accept:* tests with toys for each access pattern; clean_slug and rest_wrapper produce **no** env/file events attributed to `pkg` except the claimed ones. *Test:* `tests/sandbox/test_env_wrapper.py`.
**A6 (0.5 h) Output truthfulness**: `coverage.not_observed` lists exactly what is not implemented/active (e.g. "strace layer not active", "clock variant not run"); fixture runs set `stub=true`; timeouts/crashes → `run.error` + coverage; validate every output with `trustlens.contracts.validate` in tests.

### P1 — merged by H+16
**A7 (2 h) strace second layer** (skip with honest coverage if `strace` missing): run the trigger under `strace -f -qq -e trace=openat,connect,sendto,execve,clone -o …` inside bwrap [unverified: ptrace inside bwrap may need `--cap-add SYS_PTRACE`/same userns — test]. Do a **baseline run** of `python -c pass` with the same profile and subtract its syscall set so interpreter/pip noise is not attributed. Parse into raw events with `evidence.layer="strace"`; mark `native.load` for `.so` loaded from the package. *Accept:* `strace_layer=true` in coverage; a toy that calls `ctypes`/C-level open of the canary file is detected by strace even though the audit hook misses it. *Test:* skipif no strace.
**A8 (1.5 h) Trigger matrix**: callables with typed dummy args (str/int/bytes/list/dict/None; try 3 argument sets), class instantiation + public methods, `if __name__ == "__main__"` modules via `runpy`, console-script **CLI entry points** (`trigger="cli"`, `--help` and no-arg), subprocess timeouts, `callables_total/exercised` counters. Skip and record `native_skipped` for C extensions. *Accept:* new toy whose payload lives in a CLI entry point is triggered. 
**A9 (1.5 h) Clock variant `clock+30d`**: run call/cli triggers again with time shifted +30 days (libfaketime in sandbox if available [unverified]; else patch `time.time/datetime` via the agent + document that C-level time is not shifted). *Accept:* a "date > now+14d" gated toy fires only in this variant; events have `variant:"clock+30d"`.
**A10 (1 h) Canary-in-bytes completeness**: match canary tokens in URLs, headers, bodies (`data_head`), DNS labels (exfil via `<b32-token>.evil.invalid`), `socket.send`, `subprocess` argv (`curl -d`). Also canary decoys for `~/.config/gcloud`, `~/.docker/config.json` (additive: tell lead for capabilities docs). *Accept:* five exfil-shape toys each yield `canary_match`.
**A11 (1 h) Record fixtures for new toys** (with Dev C's packages): `python -m trustlens scan <toy> --runner live --out /tmp/x` then hand the `raw_events.jsonl`+`run_meta.json` to the lead for `schemas/examples/<name>/` (shared folder) — one PR per batch.

### P2 — only with spare time
**A12 (2 h) Loopback sinkhole** for staged payloads: inside the netns, run a tiny fake server on 127.0.0.1 (and resolve every hostname to it via `/etc/hosts`/`LD_PRELOAD`-free approach [unverified]) that returns a benign marker script; observe the second stage (`download_exec`). Must never reach the real network. **A13 (1 h)** sandbox-probe camouflage review (what a malware would test: `/proc/1/cgroup`, hostname, uptime, CPU count, `DISPLAY`) and log `sandbox_probe` events. **A14 (1 h)** performance: parallelise profiles; target < 60 s per package.

## Test commands
`make test` · `python -m pytest tests/sandbox -q` · `python -m trustlens scan bench/packages/malicious/delayed_slug --runner live --out /tmp/d` (expect exit 20) · `make demo-live`.

## Fixtures & handoffs
* To B (engine): new raw-event kinds/fields **only** via contract PR; after each P0 task merge, post "A→B: <task> merged, example: schemas/examples/<name>" in chat. B tests against `_synthetic_pth_startup` until your real events land.
* To C: tell C when a trigger/gate works so they plant the toy; C's packages are the live test inputs.
* To D: run_package signature never changes (frozen).

## Safety reminders
Run only toys and bench packages live. **Never** run `pip install`, `setup.py` or any sample on the host. No real credentials in canaries. Before running anything live on a laptop: `check_env.sh` says "network really blocked: YES". Never `pip install supply-chain-guard`. Never copy Packj (AGPL) code; Package Analysis (Apache-2.0) ideas/code only with attribution in `NOTICE`.

## Do-not-claim
Don't write "first sandbox tool" (PipCanary exists), "undetectable by malware", "catches native code" unless A7 proves it, "clock fast-forward" unless variant events exist. In `docs/SANDBOX.md` and `not_observed` state limits plainly.

## Definition of done
All P0 merged (A0–A6); P1 as time allows; every task has a test (live tests `skipif not bwrap_ok`); `ruff` + `make test` + `check_ownership --dev a` green; `docs/SANDBOX.md` layer table accurate; AUDIT.md §1 rows ticked and signed in the log with UTC date/time. Final message to the lead: tasks done, tests added, known gaps.
