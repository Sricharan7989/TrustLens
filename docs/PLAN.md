# PLAN (Owner: Dev D) — 24 h timeline (H0 = 1:30 PM kickoff; real clock times)

| Hour | Clock Time | Milestone | Owner(s) | Status |
|---|---|---|---|---|
| H0–1 | 1:30 PM – 2:30 PM | Everyone: `make setup-dev`, `check_env.sh`, `make demo`, read AGENTS.md; pick GitHub handles in CODEOWNERS; lead baseline `make audit` | all | Done |
| H1–3 | 2:30 PM – 4:30 PM | P0 tasks start (see prompts). A: real install+`.pth` diff. B: `.pth` startup rule + claim intents. C: 8 toys. D: CLI hardening, HTML v1.5, e2e suite, demo-all | all | In Progress |
| **H8** | **9:30 PM** | **Checkpoint 1: "install a package -> get its fingerprint"** — `python -m trustlens scan <pkg> --runner live` prints fingerprint + verdict; fixtures for fallback. All P0 tasks merged. | A, B, D | Planned |
| H8–16 | 9:30 PM – 5:30 AM | P1: trigger matrix, strace, env-differential variants, Datadog sample run, whitelist calibration, heatmap, presentation deck draft | all | Planned |
| H16 | 5:30 AM | Feature freeze for P2; P2 tasks (localhost web UI, --compare) evaluated only with spare time | all | Planned |
| H16–20 | 5:30 AM – 9:30 AM | Full eval (live sandbox), False-Positive audit with Wilson 95% CIs, docs completion, deck finalization | C, D, B | Planned |
| H20 | 9:30 AM – 10:30 AM | `make audit` full suite + team sign-offs | lead | Planned |
| H21 | 10:30 AM | Strict code freeze (critical bug fixes only) | all | Planned |
| H21–23 | 10:30 AM – 12:30 PM | Demo rehearsal x3 (one with Wi-Fi disabled), backup screen recording, judge walkthrough preparation | D, lead | Planned |
| H24 | 1:30 PM | Final Pitch & Judging Session | all | Planned |
