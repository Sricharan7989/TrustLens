# DEPENDENCIES

Pinned versions are those **verified to install together in a fresh venv** (Python 3.13.5, Linux x86_64, pip from `ensurepip`). Change only via lead.

## Python runtime (`requirements.txt`)
| Package | Pin | License | Purpose | Why chosen |
|---|---|---|---|---|
| PyYAML | 6.0.3 | MIT | read `capabilities.yaml`, `weights.yaml`, `labels.yaml`, whitelists | human-editable rule files; ubiquitous |
| jsonschema | 4.26.0 | MIT | validate every artifact against `schemas/` (`contracts.validate`) | contracts are the integration glue |
| setuptools | 84.2.1 | MIT | copied into the sandbox so `setup.py egg_info` can run (system python often lacks it) | install-time hooks must execute to be observed |
| wheel | 0.48.0 | MIT | same (sandboxed build of sdists) | |
| packaging | 26.3 | Apache-2.0/BSD | version/marker parsing, setuptools dependency | |

## Python dev (`requirements-dev.txt`)
| Package | Pin | License | Purpose |
|---|---|---|---|
| pytest | 9.1.1 | MIT | tests |
| ruff | 0.17.2 | MIT | lint (`pyproject.toml`) |
| pip-licenses | 5.5.5 | MIT | licensing audit table (`make audit`) |
| pip-audit | 2.10.1 | Apache-2.0 | known-vuln scan of our pins (needs network for advisories; `make audit` skips cleanly offline) |
| **guarddog** (baseline) | 3.2.0 | Apache-2.0 | static YARA/Semgrep baseline; installs `yara-python`. We exclude its 3 network-dependent rules and never run it under `--offline` |
| **pipcanary** (baseline) | 0.1.1 | MIT | sandbox-based baseline (closest competitor; **needs bwrap + strace**; shares network by default — see `eval/baselines/pipcanary.py`) |

Baselines are optional: `make eval` works without them (they show "not run"). `pip install guarddog pipcanary` conflicts were checked: none at these pins. Not used: Packj (AGPL), OSCAR (no code).

## System packages (apt)
| Package | Needed by | Notes |
|---|---|---|
| `bubblewrap` | Dev A sandbox (live runner), PipCanary | rootless; needs unprivileged user namespaces |
| `strace` | A's second tracing layer, PipCanary | **if unavailable** (it is missing on the build box): `strace_layer=false`, `coverage.not_observed` says "native code invisible", PipCanary baseline reports "unavailable". Never fake it. |
| `python3-venv` | everyone | `sudo apt install python3-venv` |
| `make`, `unzip`, `git`, `curl` | Makefile; Dev C data scripts | `sudo apt install make unzip git curl` |
| `docker` (optional) | fallback runner if userns is blocked | `--network none --read-only --cap-drop ALL` |
| `gitleaks` (optional) | `scripts/scan_secrets.sh` | grep fallback if absent |

Ubuntu 23.10+/24.04: `kernel.apparmor_restrict_unprivileged_userns=1` can make bwrap fail. `bash scripts/check_env.sh` prints the exact options.

## ⚠️ Name trap: `supply-chain-guard`
`pip install supply-chain-guard` installs a **different project** (namesjoe/chain_guard) whose wheel ships a `.pth` file that runs at every interpreter start. **Never install it.** The legitimate "supply-chain-guard" (homeofe) is an **npm** tool and is unrelated to this repo. `make audit` fails if the string appears in any install file. (Good demo slide: a `.pth` is exactly the startup-hook class we detect.)

## Datasets (not Python deps; all under gitignored `data/`)
Top-PyPI list (hugovk; `curl -L`), Datadog malicious-software-packages-dataset (Apache-2.0; seeded 100–200 sample via sparse checkout; zip password `infected`), QUT-DV25 (2.14 GB, optional calibration), OSPtrack `label_data_v2.csv` (zenodo 21853840, only if time), pypi_malregistry (no license, local backup). Skipped: MalwareBench, MPAD-NPM. See `docs/DATASETS.md`.

## Update procedure
Fresh venv → change the pin → `make setup-dev && make test && make audit` → PR to lead with the output lines.
