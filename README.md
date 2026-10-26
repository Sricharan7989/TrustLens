# TrustLens AI

**PS1 "Trust Nothing: Provenance for Your Own Dependencies"** — IOTA × Enigma hackathon, IIIT Sri City, Cybersecurity track.

TrustLens runs a Python package inside a **no-network sandbox with fake secrets (canaries)**, records what it *actually does* at install, interpreter startup, import, call and CLI, under a *dev-laptop* and a *CI* environment, compares that with what its **README/metadata claim**, and prints a verdict with an **evidence chain** and an honest **coverage** block. Rule-based, deterministic, offline, no LLM in the verdict path.

Verdicts: `MALICIOUS-EVIDENT` (exit 20) · `SUSPICIOUS` (10) · `INCONCLUSIVE` (10, we abstain when we could not observe enough) · `BENIGN-CONSISTENT` (0, "consistent with stated purpose within the listed coverage", not "safe").

## Quickstart (3 steps)
```bash
git clone <repo> && cd trustlens
make setup-dev            # 1. venv + pinned deps (+ GuardDog/PipCanary baselines); needs python3-venv
make demo                 # 2. scans 4 toy packages end to end on recorded fixtures -> reports/demo/*/report.html
make eval                 # 3. PS1-Bench metrics + heatmap vs baselines -> reports/eval/summary.md, heatmap.html
```
Real sandbox (toys only!): `bash scripts/check_env.sh` then `make demo-live`. Needs `bubblewrap` (`sudo apt install bubblewrap strace`). On Ubuntu 24.04 you may need the userns workaround the script prints.

## Status: starter kit v0 (what is real and what is stubbed)
| Part | Status |
|---|---|
| Contracts, schemas, fixtures, tests, audit | real |
| Sandbox live runner (bwrap, canaries, dev/ci, `setup.py egg_info`, import-all, call-all, audit hook, env wrapper) | **v0 real**; real `pip install`+`.pth` diff, fresh-startup, strace, clock+30d, CLI trigger, sinkhole: Dev A tasks |
| Claims extractor, normalizer, rules, verdict ladder | **v0 real** (keyword intents, 10 rules) — Dev B extends |
| Report (HTML/JSON/text), CLI | v0 real — Dev D polishes |
| PS1-Bench | 4 starter packages — Dev C grows to 8–10 malicious + 15–20 clean |
| `make demo` / `make eval` | run on **recorded fixtures** (real bwrap recordings of the toys); marked `stub:true` in `run_meta` |

## Layout & how to work
Read **`AGENTS.md`** (ownership, rules), **`docs/CONTRACTS.md`** (interfaces), then your prompt in **`prompts/`**. Four devs A–D own disjoint folders; the lead merges. `AUDIT.md` + `make audit` guard safety, licensing and claims. `DEPENDENCIES.md` lists every dependency (and the `supply-chain-guard` name trap). `docs/` has architecture, limitations, demo script, and the PPT outline.

## Safety
Malware samples never run on the host: only inside bwrap, network off, fake HOME, data in gitignored `data/`. Never `pip install supply-chain-guard`. Packj is AGPL: never copied.

## AI-assistance disclosure
This repo was scaffolded with coding agents for a hackathon; every dev reviews generated diffs. License: MIT.
