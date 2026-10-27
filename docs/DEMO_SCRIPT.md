# DEMO_SCRIPT (Owner: Dev D) — 5 minutes, single laptop, offline-ready

**Before going on stage:**
1. Ensure dependencies are ready: `make setup-dev`
2. Pre-generate all demo artifacts: `make demo && make demo-all && make demo-compare && make eval`
3. Check sandbox capability: `python -m trustlens check-env`
   * If bwrap is available: use `--runner live` (or `auto`)
   * If bwrap is unavailable: use `--runner fixture` and state out loud: *"Events replayed from a recorded fixture run."*
4. Open the following tabs in your browser:
   * `reports/demo/evil_slug/report.html`
   * `reports/demo/delayed_slug/report.html`
   * `reports/compare_demo.html`
   * `reports/eval/heatmap.html` (or `reports/eval/summary.md`)
5. Have a backup screen recording saved locally outside git.

---

## Minute-by-Minute Stage Walkthrough

| Time | Action / Terminal Command | Spoken Narrative & Stage Cue | Visual Display |
|---|---|---|---|
| **0:00 - 0:30** | Advance to Slide 2 | *"Every time you run `pip install`, you are granting unverified code full execution rights on your machine. Attackers hide inside setup.py scripts, .pth startup hooks, and CI-only execution gates. Static analysis is easily defeated by base64 obfuscation; signatures lag days behind."* | Slide 2 (Problem & Attack Surface) |
| **0:30 - 1:15** | `python -m trustlens scan bench/packages/malicious/evil_slug --runner live` *(or fixture)* | *"Here is TrustLens scanning `evil_slug`. Notice the loud runner mode banner. We observe exit code 20 — BLOCK. Let's look at why."* | Terminal output: `MALICIOUS-EVIDENT` (Exit 20), runner mode banner |
| **1:15 - 2:00** | Switch to tab: `reports/demo/evil_slug/report.html` | *"The package claims in its README to be a 'tiny string utility that turns titles into URL slugs'. But during the install phase, it accessed `~/.ssh/id_rsa` and attempted an HTTP exfiltration. TrustLens baited it with a canary SSH key, and the canary token appeared directly in the outgoing request payload. That is deterministic proof, not a score."* | Evidence Chain card, Timeline lanes, Canary-in-bytes badge |
| **2:00 - 2:45** | Switch to tab: `reports/demo/delayed_slug/report.html` | *"Next: evasion techniques. `delayed_slug` appears completely benign on a developer's laptop, but executes base64-encoded payloads when run in CI. Because TrustLens runs differential environments (`dev` vs `ci`), it catches the discrepancy and flags the environmental trigger."* | Dev vs CI timeline columns, `env_differential` pill |
| **2:45 - 3:30** | Switch to tab: `reports/compare_demo.html` | *"How do we prevent false alarms? Look at this side-by-side view. `rest_wrapper` makes network requests and reads environment variables. Yet it receives a clean PASS (exit code 0). Why? Because its README licenses REST API calls. Stated intent licenses observed behavior."* | `compare_demo.html` side-by-side PASS vs BLOCK |
| **3:30 - 4:00** | Scroll down to Coverage Block in report | *"Notice the coverage block. If a package cannot be installed or executed, TrustLens does not claim it is clean. It reports `INCONCLUSIVE` with an honest list of unobserved phases. We abstain instead of guessing."* | `not_observed` list, Coverage block |
| **4:00 - 4:40** | Switch to tab: `reports/eval/heatmap.html` / `summary.md` | *"We evaluated TrustLens on PS1-Bench. Across planted triggers, gated branches, and clean controls, we report recall and false-positive rates with Wilson 95% confidence intervals. Datasets are strictly for calibration and evaluation, never model training."* | PS1-Bench heatmap & metrics table |
| **4:40 - 5:00** | Advance to Slide 10 | *"In summary: deterministic proof over suspicion, environment-differential execution, and claims-aware licensing. Thank you. We welcome your questions."* | Architecture & Roadmap slide |

---

## Contingency & Fallback Plans

* **Wi-Fi Down**: Entire pipeline is offline by default (`--offline`). Zero network requests are made.
* **Sandbox / Kernel Namespace Issue**: Add `--runner fixture` to any command. All fixtures replay authentic recorded runs. Say: *"We are running fixture replay mode on pre-recorded bwrap traces."*
* **Browser Rendering**: Reports are self-contained single files with inline CSS and zero external CDN links; they render cleanly offline.

---

## Approved Terminology & Mandatory Phrases
* Always prefix novel capabilities with *"to our knowledge"*.
* Say *"consistent with stated purpose within tested coverage"*, do not claim *"100% safe"* or *"catches all malware"*.
* Say *"canary-in-bytes deterministic proof"*.
