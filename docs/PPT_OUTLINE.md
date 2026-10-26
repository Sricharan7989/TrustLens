# PPT_OUTLINE (Owner: Dev D; lead reviews against AUDIT.md §5) — 10 slides + 2 backup

Style: one message per slide, ≤ 25 words of body text, one visual. Numbers only from `reports/eval/results.json`. Fill `[[...]]` at H+20.

1. **Title** — "TrustLens AI: trust nothing, observe everything". PS1 · Cybersecurity track · team names · IIIT Sri City IOTA × Enigma. Visual: logo + one-line promise: "Run it, bait it, compare it with what it claims."
2. **Problem** — Dependencies run code at *install*, *every interpreter start (.pth)*, *import*, *call*. Static scanners are evaded by obfuscation and gating; signatures lag. Visual: timeline of phases with attack examples (install-script exfil, `.pth` startup hook, CI-only payload). Cite real incidents only if verified in the deck notes.
3. **Idea** — "Environment-differential execution + claims-vs-behavior". Visual: the mermaid pipeline from AGENTS.md §2 simplified to 5 boxes.
4. **How the sandbox works** — bwrap, no network, fake HOME with canaries, dev vs CI profiles, trigger matrix, audit hook + env wrapper (CPython has no env-read event), real install + site-packages diff, strace layer, clock +30d. Visual: layered diagram. Mark each layer ✅ done / 🔶 partial [[fill from run_meta.coverage]].
5. **Claims → licensed behavior** — README sentence → intent → allowed capabilities; observed − licensed = findings. Visual: split screen of `rest_wrapper` (PASS) vs `evil_slug` (BLOCK) with the quote highlighted.
6. **Verdicts you can trust** — ladder MALICIOUS-EVIDENT / SUSPICIOUS / INCONCLUSIVE / BENIGN-CONSISTENT; "BLOCK needs canary-in-bytes or ≥2 independent signals"; abstention + coverage block. Visual: the HTML report screenshot.
7. **Demo** (live or recorded; say which) — evil_slug, delayed_slug, rest_wrapper per DEMO_SCRIPT.md.
8. **Evaluation** — PS1-Bench: [[n_mal]] planted toys (trigger × gate × obfuscation) + [[n_clean]] clean controls; + [[n]] Datadog sample (seed 1337) + [[n]] top-PyPI clean. Metrics: recall [[x/y]], FP [[k/n (95% CI a–b)]], INCONCLUSIVE [[m]], runtime [[s]]. Visual: heatmap. Footnote: datasets used for testing/calibration, not training; PS1-Bench is ours.
9. **Comparison (factual, how-run noted)**

   | | TrustLens | GuardDog 3.2.0 | PipCanary 0.1.1 | Packj (CLI, optional) |
   |---|---|---|---|---|
   | Approach | sandbox + claims | static YARA/Semgrep | sandbox + strace | static+dynamic |
   | Recall on PS1-Bench | [[ ]] | [[ ]] | [[ ]] | [[ ]] |
   | FP on clean (k/n, CI) | [[ ]] | [[ ]] | [[ ]] | [[ ]] |
   | Env-differential | yes (dev/ci, +30d: [[status]]) | no | [[verify]] | no |
   | Compares with README claims | yes | no | no | no |
   | Abstains / coverage block | yes | no | no | no |
   Rows marked [[verify]] must be checked against the tool before presenting. "Not run" if a baseline was unavailable.
10. **Limitations & roadmap** — from `docs/LIMITATIONS.md` (gated code, no server replies, native code, sandbox-aware malware, keyword claims). Roadmap: npm, loopback sinkhole for staged payloads, dependency-tree attribution, CI integration (`pre-commit`/GitHub Action), richer claim model.
11. **Team & thanks** — who built what (A sandbox, B engine, C bench/eval, D CLI/report/docs, lead). Repo link, MIT.

Backup B1: pitch-claim defenses (what we do **not** claim: see AGENTS.md §9). B2: architecture detail + contracts + audit process (AUDIT.md) + licensing table.

**Pitch claims (each with "to our knowledge"):** environment-differential execution · startup-hook-aware real install · README-licensed behavior with evidence chains · honest abstention + coverage + own benchmark · proof-not-suspicion.
**Do not claim:** first sandbox tool, first FP reduction, first eval suite, "nobody compares claims with code", 100%/zero FP.
