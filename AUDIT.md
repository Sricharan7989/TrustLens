# AUDIT.md — security, quality and integrity checklist (Owner: Lead; every dev signs their rows)

Run `make audit` (automated rows marked **[auto]**) then tick the manual rows. Append one entry to the log (§10) each time. When to run: before each merge to `main` (auto), at checkpoints (full), at **H+20** (full, before the freeze) and before the pitch (full + §8).
Timestamps: use UTC (`date -u`) in the log; add IST in brackets if you like. (The user team works in IST = UTC+5:30.)

## 1. Sandbox-escape & host-safety (Dev A signs)
| # | Check | How | Auto |
|---|---|---|---|
| 1.1 | Network really blocked inside sandbox | `bash scripts/check_env.sh` prints `network really blocked: YES`; also `python -m pytest tests/sandbox` | [auto-ish] |
| 1.2 | Isolation flags present: `--unshare-net --unshare-pid --unshare-uts --unshare-ipc --clearenv --die-with-parent`, no `--bind` of real HOME, `/etc`, `~/.ssh` | read `trustlens/sandbox/*.py`; `scripts/audit.sh` check #14 | [auto] (flags) |
| 1.3 | Only toy packages ran live so far; no real malware executed on the host | `ps`/history review; Dev C confirms samples only touched via `extract_in_sandbox.sh` and the runner | manual |
| 1.4 | Canaries are fake and unique per run; no real credential in fixtures/logs | `scripts/scan_secrets.sh`; grep fixtures for real-looking keys | [auto] |
| 1.5 | Package-controlled strings never reach a shell (`shell=True`, `os.system`, f-string into bash) | `grep -rn "shell=True\|os.system" trustlens eval bench/tools` → must be empty or justified | manual |
| 1.6 | Escape attempts considered: write to `/proc`, symlink out of the package dir, huge file/fork bomb → timeouts + `--die-with-parent`, tmpfs sizes/ulimits | test with a toy that tries each; record result | manual |
| 1.7 | Report HTML cannot execute package content (escaping, no remote assets) | `tests/e2e` hostile-string test | [auto] |
| 1.8 | Sandbox self-test is run on **each** laptop that executes anything | each dev pastes `check_env.sh` output in the log | manual |

## 2. Malware handling (Dev C signs)
| # | Check | Auto |
|---|---|---|
| 2.1 | `data/`, `samples/`, `*.zip`, `*.whl`, `*.tar.gz` untracked and ignored | [auto] |
| 2.2 | Datadog zips fetched by sparse checkout only (not the repo zip); password `infected`; extraction only via `scripts/extract_in_sandbox.sh` | manual |
| 2.3 | Clean controls downloaded via PyPI JSON API + sha256 check; never `pip download`/`pip install` on the host | manual (read `bench/tools/pick_clean.py`) |
| 2.4 | Samples not uploaded to chat/cloud/slides; deck shows package *names* and our findings only | manual |
| 2.5 | Planted toys use only RFC 5737 / `.invalid` targets | [auto] `tests/bench` |

## 3. Licensing audit
| Component | License | Allowed use | Status | Verified by / when |
|---|---|---|---|---|
| Packj | **AGPL-3.0** | CLI comparison only; **no copied code** | [auto] no `import packj` | |
| OSCAR | none (paper only) | reimplement ideas, cite | manual | |
| malregistry (pypi_malregistry) | none | local only, never committed | [auto] not tracked | |
| Package Analysis | Apache-2.0 | ideas/code with attribution (`NOTICE`) | manual: any copied code carries attribution | |
| GuardDog | Apache-2.0 | baseline CLI | | |
| PipCanary | MIT | baseline CLI | | |
| Datadog dataset | Apache-2.0 | test samples, not redistributed | | |
| QUT-DV25 | per Dataverse record | calibration only; cite | manual: read the record's license | |
| OSPtrack | CC-BY-4.0 | calibration/inspiration; cite | | |
| Our deps | `reports/audit/licenses.md` | no GPL/AGPL | [auto] pip-licenses | |
`NOTICE` and `DEPENDENCIES.md` must match this table.

## 4. Hackathon-rule compliance (Lead signs)
☐ Every line is written during the hackathon window or is a clearly attributed third-party/open-source piece (list in `NOTICE`). ☐ Pre-existing ideas/papers cited in the deck. ☐ Team of 5, each member can explain their module. ☐ Cybersecurity track + PS1 stated on slide 1. ☐ AI-assistant use disclosed if the rules ask (we used coding agents; see README). ☐ Repo public/private as the organisers require; no secrets; license MIT present. ☐ Demo runs from a clean clone in < 5 min (`README.md` quickstart tested on a second laptop). ☐ `--offline` works with Wi-Fi off.

## 5. Claims audit (Dev D + Lead sign; run on README, docs/, slides, DEMO_SCRIPT)
| # | Check | Auto |
|---|---|---|
| 5.1 | No banned phrase (first sandbox / first FP-reduction / first eval suite / nobody compares claims / 100% / zero FP / safe) | [auto] grep |
| 5.2 | Every number on a slide traces to `reports/eval/results.json` or `summary.md`, with date | manual |
| 5.3 | FP rate always shown as `k/n` with Wilson 95% CI | manual |
| 5.4 | Fixtures/stubs/synthetic cases labelled; live vs fixture runs never mixed in one table without a column saying so | manual |
| 5.5 | Comparison table states exactly how GuardDog/PipCanary were run (version, flags, mode, shared-network caveat, `unavailable` shown as "not run") | manual |
| 5.6 | "Limitations" slide matches `docs/LIMITATIONS.md` and the `coverage.not_observed` of the demo run | manual |
| 5.7 | npm appears only as roadmap | manual |
| 5.8 | Competitors named correctly: PipCanary (sandbox), GuardDog (static + FP-reduction), SemanticSentinel (claims-vs-code), Package Analysis, OSCAR, Packj | manual |

## 6. False-positive audit procedure (Dev B + C sign)
1. Run `make eval-live` on the clean set (15–20 controls incl. noisy-benign + 30 top-PyPI). 2. For **every** non-PASS clean package: open `report.html`, find the finding, classify: *(a) true noise → whitelist rule in `engine/noise_whitelist.yaml` with reason+source*, *(b) claim parser gap → fix intent keywords in `capabilities.yaml` via contract PR*, *(c) real behavior, mis-labelled → fix label with evidence*, *(d) genuine engine bug → regression test*. 3. Never tune on the malicious set only; re-run the malicious set after each whitelist change; no whitelist rule may remove an event that carries a canary. 4. Record before/after FP count `k/n` in the log. 5. Report INCONCLUSIVE separately (abstention rate), never silently as PASS or as FP. 6. Hold out 5 clean packages you did **not** use when tuning for the final number.

## 7. Contract conformance (Lead signs) [auto]
`python scripts/audit_contracts.py`: validates every example/fixture against `schemas/`, checks `bench/labels.yaml`, replays all labelled packages through the real pipeline (claims→fingerprint→verdict) and compares the verdict with `expected_verdict`. Also: `reports/eval/results.json` validates when present.

## 8. Dependencies & secrets
☐ [auto] all deps pinned. ☐ [auto] `pip-licenses` clean of GPL/AGPL. ☐ [auto, online] `pip-audit -r requirements.txt` (record result or "offline"). ☐ [auto] secrets scan (`gitleaks` if installed else grep). ☐ [auto] no `supply-chain-guard` in install files. ☐ New dep? row added in DEPENDENCIES.md. ☐ `git log -p | grep -i "BEGIN .*PRIVATE"` shows only canary placeholders.

## 9. Sign-off (each dev: tick only after running the checks for your area)
| Area | Owner | Rows | Signed (initials) | Date (UTC) | Time (UTC) | Notes |
|---|---|---|---|---|---|---|
| Sandbox & host safety | Dev A | §1 | | | | |
| Fingerprint/claims/engine, FP audit | Dev B | §6, §7 (engine part) | | | | |
| Bench, data, malware handling, eval numbers | Dev C | §2, §3 (data rows), §6 | | | | |
| CLI/report/docs/claims | Dev D | §5, §1.7 | | | | |
| Licensing, rules, deps, secrets, contracts | Lead | §3, §4, §7, §8 | | | | |
| **Release go/no-go** | Lead | all | | | | |

## 10. Log template (append; newest last)
```
### YYYY-MM-DD HH:MM UTC — <name>/<role> — <checkpoint or merge id>
make audit: PASS|FAIL (paste the "AUDIT AUTOMATED CHECKS" line)   make test: <N passed>   make demo: 4 verdicts OK?
check_env.sh on <machine>: bwrap OK|NO, strace OK|NO, network blocked YES|NO
Manual rows ticked: 1.3 1.5 ... | Findings: <id: description, severity, owner, fix commit>
FP audit (if run): clean set k/n flagged, INCONCLUSIVE m/n, changes made: ...
Open risks: ...
```
Severity: **S1** sandbox escape / real credential leak / malware on host (stop everything, tell lead) · **S2** false claim in pitch material, license breach · **S3** contract drift, flaky test · **S4** cosmetic.

### Log


### 2026-10-26 18:32 UTC — Claude (coding agent, for Lead) — follow-up check on lead/followup-fixes over main eedb335 (PRs #6, #7, #8 merged)
make audit: AUDIT AUTOMATED CHECKS: PASS   make test: 322 passed, 21 skipped (bwrap/docker unavailable)   make demo: 20, 20, 0, 0 OK   ruff: clean   audit_contracts: 46 example files, 0 problems
check_env.sh on cloud VM: bwrap NO, strace OK (host only), network n/a. No live sandbox run.
Manual rows ticked: none (agent cannot sign; owners sign §9 after their own checks).
Findings: S3 PR #6 regressions vs main (aliased `os` access, DB_PASSWORD/PRIVATE_KEY names) PR #6 merged without the fix; fixed on lead/followup-fixes. S3 PR #7 tag stripping removed `<string>`/`<module>` and code comparisons from JSON evidence; PR #7 merged without the fix; narrowed to active HTML on lead/followup-fixes. S3 strace split lines dropped baseline helper execs (cut/tr flake) and package syscalls; fixed in PR #8 (merged). S3 `make demo-all` reports 22 MISMATCH on main as well: the 22 bench packages without a recording come out INCONCLUSIVE; not fixed.
FP audit: not run (needs `make eval-live` on a bwrap machine).
Open risks: fixture eval only decides 4/26 packages; 22 bench packages have no recording, so pitch numbers need `make eval-live` (and recordings) on Linux. Docker fallback never executed live.
