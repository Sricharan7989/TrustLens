# ENGINE notes (Owner: Dev B) — rules table

Rule names are frozen contract (reports and heatmap use them): see `docs/CONTRACTS.md` §3.
One row per rule: `name` · `signal_class` · `trigger condition` · `licensed-by` · `FP risk` · `test`.

| Rule Name | Signal Class | Trigger Condition | Licensed By | FP Risk | Test |
|---|---|---|---|---|---|
| `startup_hook` | `startup_hook` (strong) / `info` | `.pth` or `sitecustomize` line executing code (`import`, `exec`, `base64`); plain path `.pth` is `info` | None | Low (setuptools `.pth` paths are plain paths without code) | `tests/engine/test_engine.py::test_synthetic_pth_startup_detailed`, `test_plain_path_pth_is_info_not_strong` |
| `persistence` | `persistence` (strong) | File write to shell rc (`~/.bashrc`), cron, autostart, systemd user units, or `.git/hooks` | None | Very low | `tests/engine/test_engine.py::test_persistence_detection` |
| `download_exec` | `dropper` (strong) | File written by package and subsequently executed via subprocess, `dyn.exec`, or imported | None | Very low | `tests/engine/test_engine.py::test_download_exec_detection` |
| `canary_read_then_network` | `canary_access` (strong) | Fake secret canary read (`~/.ssh`, `~/.aws`, env tokens) followed by network attempt in same profile | None | Extremely low (fake canaries only) | `tests/engine/test_engine.py::test_evil_slug_has_canary_in_bytes_and_evidence_chain` |
| `canary_in_outgoing_bytes` | `canary_in_bytes` (strong, instant BLOCK) | Exact canary token substring discovered in outgoing network request bytes or URL | None | Zero (ground truth proof) | `tests/engine/test_engine.py::test_evil_slug_has_canary_in_bytes_and_evidence_chain` |
| `network_unclaimed` | `network_unclaimed` (strong) | Network attempt during a phase where network capability is not licensed by package claims | `http_client`, `downloader`, `ssh_tool` (in `import`, `call`, `cli`) | Low | `tests/engine/test_engine.py::test_rest_wrapper_network_is_claim_licensed_not_a_finding` |
| `decoded_exec` | `decoded_exec` (strong) | Runtime compilation or execution (`dyn.exec`, `dyn.compile`) of decoded/eval'd code | `cli_tool`, `native_ext` | Medium (some parsers/shims use `exec`) | `tests/engine/test_engine.py::test_delayed_slug_needs_ci_profile_to_show` |
| `env_differential` | `env_differential` (strong) | Capability observed conditionally in `ci` profile or `clock+30d` variant, but absent in baseline `dev` | None | Low | `tests/engine/test_engine.py::test_delayed_slug_needs_ci_profile_to_show` |
| `capability_not_claimed` | `mismatch_other` (weak) | Sensitive filesystem read, secret env read, or subprocess observed without license in claims | Matching claim intents | Medium | `tests/engine/test_engine.py::test_expected_verdicts` |
| `sandbox_probe` | `sandbox_probe` (weak) | Package reads CI/container env vars or inspects `/proc`, dockerenv, uptime | `system_info` | Medium | `tests/engine/test_engine.py::test_delayed_slug_needs_ci_profile_to_show` |

## Scoring Knobs & Sensitivity Analysis (Task B8)

All scoring knobs reside strictly in `trustlens/engine/weights.yaml` (no magic numbers in code).
Below is the sensitivity analysis testing a ±20% variation on each parameter across our baseline fixtures (`evil_slug`, `delayed_slug`, `clean_slug`, `rest_wrapper`, and `_synthetic_pth_startup`):

| Parameter | Baseline | -20% Value | +20% Value | Verdict Changes on Fixtures | Sensitivity Rationale |
|---|---|---|---|---|---|
| `suspicious_threshold` | 4.0 | 3.2 | 4.8 | **None** | Malicious packages score ≥ 18.0; clean packages score 0.0. No threshold flip occurs on any fixture. |
| `canary_multiplier` | 2.0 | 1.6 | 2.4 | **None** | `evil_slug` triggers `canary_in_bytes` which directly triggers `MALICIOUS-EVIDENT` irrespective of score. |
| `env_differential_multiplier` | 1.5 | 1.2 | 1.8 | **None** | `delayed_slug` generates 3 independent strong signals; multiplier change affects total score but not BLOCK ladder verdict. |
| `startup_escalation_multiplier` | 1.5 | 1.2 | 1.8 | **None** | `_synthetic_pth_startup` has 3 independent signals; verdict remains `MALICIOUS-EVIDENT`. |
| `dep_multiplier` | 0.7 | 0.56 | 0.84 | **None** | Only discounts non-canary dependency findings; does not affect clean or malicious verdicts. |
| `block_min_independent_signals` | 2 | 1 (strict) | 3 (conservative) | **None** at 3: `evil_slug` has canary-in-bytes; `delayed_slug` has 3 classes; `_synthetic_pth_startup` has 3 classes. | Dual-signal threshold prevents any single heuristic from blocking. |
| `min_callable_ratio_for_benign` | 0.5 | 0.4 | 0.6 | **None** | `clean_slug` and `rest_wrapper` exercise 100% (1/1) of declared callables. |

## False-Positive Calibration Loop with Dev C (Task B9)

When Dev C flags a clean package during benchmark evaluations:
1. **Triage Classification**:
   - **True Noise (Benign build / platform noise)**: Add a targeted rule to `trustlens/engine/noise_whitelist.yaml` containing mandatory fields: `capability`, `path_glob` / `host_glob` / `env_glob`, `reason`, and `source`.
   - **Claim Gap**: If legitimate behaviour was described in the README using unexpected vocabulary, propose a contract update for intent keywords in `schemas/capabilities.yaml` via Lead PR.
   - **Engine Classification Bug**: Add a regression test in `tests/engine/test_engine.py` recreating the exact event chain, then refine normalization or attribution logic.
2. **Guaranteed Canary Protection**:
   - The whitelist loader enforces that no rule can ever whitelist or drop an event carrying a canary hit (`canary_match` or `canary_in_bytes`).
3. **Regression Safety**:
   - Run `make test` and `make demo` after any whitelist or scoring adjustment to ensure 0% regression in malicious package detection.


