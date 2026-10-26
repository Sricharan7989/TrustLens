# PROMPT — PM / LEAD (5th teammate): contracts, integration, audit  (paste into your coding agent or use as your checklist)

## Role
You are the **Lead/PM** of TrustLens AI. You own the contracts and the merge train; you are the only person who touches shared files (`AGENTS.md`, `AUDIT.md`, `OWNERS.yaml`, `docs/CONTRACTS.md`, `schemas/**`, `trustlens/contracts.py`, `pyproject.toml`, `requirements*.txt`, `DEPENDENCIES.md`, `prompts/**`, `scripts/{audit*,make_examples,check_ownership,scan_secrets,build_kit}`, `schemas/examples/**`, `tests/contracts/**`). You keep `main` green, enforce honest claims, and run the audits. You do not write product features.

## Read first
`AGENTS.md` · `docs/CONTRACTS.md` · `AUDIT.md` · `OWNERS.yaml` · all four dev prompts (skim) · `docs/PLAN.md`.

## Hour 0 (do in this order)
1. `make setup-dev && make demo && make test && make audit` — expect green; paste the output in the AUDIT.md log (UTC). 2. Create the GitHub repo, push `main`, protect it (PRs only, 1 approval = you; linear history). Replace handles in `.github/CODEOWNERS`. 3. Each dev: `bash scripts/check_env.sh` → paste output to you. **Any laptop without a working bwrap + "network really blocked: YES" must not run samples** — plan: Dev A's Docker fallback or fixtures. 4. Assign A/B/C/D to teammates; send each their prompt file + `AGENTS.md`. 5. Remind everyone: `git switch -c dev-x/<topic>`; rebase policy; `check_ownership.py`.

## Merge order & integration (the train)
Merge small PRs in this order each cycle (every 60–90 min), always rebase-merge (no merge commits), then run `make test && make demo && make audit` on `main`:
1. **Lead contract PRs** (schemas/capabilities/CONTRACTS, regenerate fixtures with `make fixtures`) — first, so everyone rebases onto the new contract.
2. **A** (producer): sandbox changes + new raw events + recorded fixtures.
3. **B** (consumer of A): claims/fingerprint/engine; re-run B's tests against A's new fixtures.
4. **C** (bench/eval): new toys, labels, eval harness (needs A+B to score).
5. **D** (consumer of all): CLI/report/docs/e2e.
6. **Lead** audit/docs fixes. Tag: `cp1` (checkpoint 1), `rc1` (H+21), `final`.
Rule: a consumer merges **after** its producer; never merge a PR with failing `make test`, ownership violations, or a contract change not in `docs/CONTRACTS.md`. Conflict appears? Someone edited a file they don't own: revert that part, don't resolve silently.

## Checkpoints
* **Checkpoint 1 — tonight 9:30 PM IST: "install a package → get its fingerprint".** Verify 2 h before: `python -m trustlens scan bench/packages/malicious/evil_slug --runner live --format text` on the demo laptop prints events + fingerprint + verdict; `make demo` fallback ready; tag `cp1`; slide of the pipeline ready (D).
* **H+8**: all P0 merged; **H+16**: P1 merged; **H+20**: full audit + eval-live; **H+21**: freeze; **H+22–24**: rehearse.

## Daily/periodic checklist (every merge cycle)
☐ `git fetch && git log origin/main --oneline | head` ☐ each open PR: `python scripts/check_ownership.py --dev <x> --base origin/main` ☐ `make test` ☐ `make demo` shows 4+ verdicts with expected exit codes ☐ `make audit` PASS ☐ `make fixtures` produces no diff unless a contract changed ☐ no `data/`, zips, venvs, secrets in the diff (`git diff --stat`) ☐ new deps? pinned + DEPENDENCIES.md row + license ok ☐ chat status: who is blocked, who waits for whom.

## Contract-change PRs (you are the gate)
Respond within 15 min. Accept only additive/optional changes; update `docs/CONTRACTS.md` (+ changelog line), `schemas/*.json`, examples, `tests/contracts`; run `make fixtures && make test`; announce "contract #N: <summary>; A/B/C/D must <action>". Reject renames/removals unless the whole team agrees in chat.

## Audits (AUDIT.md)
* Baseline at H0; full at each checkpoint, at **H+20**, and before the pitch. Collect each dev's sign-off (UTC date/time) in AUDIT.md §9. Run §3 licensing table (Packj not copied; malregistry untracked; attributions in `NOTICE`), §4 hackathon-rule compliance (read the organisers' rules again at H+12 and H+20; check AI-assistance disclosure requirement), §5 claims audit with D, §6 FP audit with B+C, §8 secrets/deps.
* Severity S1 (sandbox escape / real credential leak / malware on host) ⇒ stop all live runs, tell everyone, fix, log.

## Risk watchlist
bwrap blocked on Ubuntu 24.04 userns (fallback Docker/fixture) · strace missing (document, baseline "not run") · pipcanary shares network (never on malware) · QUT 2.14 GB download on campus Wi-Fi (start early, optional) · Datadog sample extraction password (`infected`) · FP rate on noisy-benign (B+C loop) · merge conflicts from someone "fixing" a neighbour's file · deck numbers not traceable · demo depends on live runner (always have fixture fallback + recording) · `pip install supply-chain-guard` by mistake.

## Final deliverables (H+22)
`make kit` zip · repo tag `final` · `reports/eval/{results.json,summary.md,heatmap.html}` with UTC date · deck + backup video · AUDIT.md log complete · sign-offs filled.

## Safety/licensing/do-not-claim reminders
Never execute samples on the host; Packj AGPL (CLI-compare only, no code); OSCAR no code; Package Analysis attribution; no "first sandbox/first FP-reduction/first eval suite/nobody compares claims"; "to our knowledge"; honest `INCONCLUSIVE`.
