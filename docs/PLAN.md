# PLAN (Owner: Dev D) — 24 h timeline (H0 = kickoff; fill real clock times)

| Hour | Milestone | Owner(s) |
|---|---|---|
| H0–1 | Everyone: `make setup-dev`, `check_env.sh`, `make demo`, read AGENTS.md; pick GitHub handles in CODEOWNERS; lead baseline `make audit` | all |
| H1–3 | P0 tasks start (see prompts). A: real install+`.pth` diff. B: `.pth` startup rule + claim intents. C: 8 toys. D: report/CLI polish | all |
| **9:30 PM** | **Checkpoint 1: "install a package → get its fingerprint"** — `python -m trustlens scan <pkg> --runner live` prints fingerprint + verdict; fixtures for fallback | A, B, D |
| H8 | all P0 merged | all |
| H8–16 | P1: trigger matrix, strace, env-differential variants, Datadog sample run, whitelist calibration, heatmap | all |
| H16 | feature freeze for P2; P2 only with spare time | |
| H16–20 | full eval (live), FP audit, docs, deck | C, D, B |
| H20 | `make audit` full + sign-offs | lead |
| H21 | code freeze (bug fixes only) | |
| H21–23 | demo rehearsal x3, backup recording | D, lead |
