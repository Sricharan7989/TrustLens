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

