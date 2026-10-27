# PPT_OUTLINE (Owner: Dev D; lead reviews against AUDIT.md §5) — 10 slides + 2 backup

**Slide Presentation Guideline:** One primary takeaway per slide, high visual contrast, quantitative values cited directly from `reports/eval/results.json` (as of 2026-10-26).

---

### Slide 1: Title & Core Thesis
* **Title:** TrustLens AI: Trust Nothing, Observe Everything
* **Subtitle:** Behavioral Provenance for Python Dependencies (PS1: IIIT Sri City IOTA × Enigma, Cybersecurity Track)
* **Visual:** Minimal architecture logo + core tagline: *"Run it in isolation, bait it with canaries, compare what it does with what it claims."*
* **Speaker Note:** "Supply chain attacks do not ask for permission. We do not guess whether code looks bad; we observe what it actually executes."

---

### Slide 2: The Attack Surface (Why Static Analysis Fails)
* **Message:** Dependencies execute hostile code before you ever call an import.
* **Attack Phases Illustrated:**
  1. `setup.py` / install phase execution (e.g. `evil_slug` credential harvester)
  2. Interpreter startup hooks via `.pth` files (e.g. LiteLLM-style persistent backdoor)
  3. Conditional gating (e.g. `delayed_slug` executing only inside CI environments)
  4. Base64 / dynamic runtime obfuscation
* **Visual:** Attack lifecycle timeline highlighting where signatures lag and static AST scanners are blinded.

---

### Slide 3: The TrustLens Core Architecture
* **Message:** Environment-Differential Sandbox + Claims-Aware Licensing.
* **Pipeline (5 deterministic stages):**
  1. `Sandbox (Dev A)`: Rootless `bwrap`, zero network, fake credentials (SSH, AWS, npmrc), dev vs CI profiles.
  2. `Normalizer (Dev B)`: CPython audit hooks + environ wrapper -> 12 normalized capability classes.
  3. `Claim Extractor (Dev B)`: Rule-based extraction of declared intent from README/metadata.
  4. `Mismatch Engine (Dev B)`: Observed behavior minus stated claims -> deterministic verdict ladder.
  5. `Reporting & CI (Dev D)`: Evidence chains, phase x profile timeline lanes, SARIF 2.1.0 output.
* **Visual:** 5-box flowchart linking Sandbox to Engine to Report.

---

### Slide 4: Sandbox Isolation & Baiting
* **Message:** Proof over suspicion: Canary tokens create forensic evidence.
* **Sandbox Layers:**
  * Rootless Linux `bwrap` (`--unshare-net`, `--unshare-pid`, `--clearenv`, fake `$HOME`)
  * Fake secrets planted: SSH private key, AWS credentials, npm token, GitHub tokens.
  * Audit hook agent (`sys.addaudithook`) + custom `os.environ` wrapper for environment read tracking.
  * Offline differential execution: Developer Laptop vs CI environments.
* **Visual:** Layered security model diagram showing network blocked at kernel boundary.

---

### Slide 5: Claims License Behavior (Eliminating False Positives)
* **Message:** A network request is only malicious if the package didn't claim it.
* **Side-by-Side Comparison:**
  * `rest_wrapper` (Clean Control): Makes HTTP calls & reads API tokens. **PASS (Exit 0)** because its README licenses REST client capabilities.
  * `evil_slug` (Malicious Plant): Claims string slugification, reads SSH key and exfiltrates. **BLOCK (Exit 20)** because capabilities contradict stated purpose.
* **Visual:** Dual-column view from `reports/compare_demo.html`.

---

### Slide 6: The Verdict Ladder & Honest Abstention
* **Message:** Clear, rule-based verdicts with transparent boundaries.
* **Ladder Levels:**
  * `MALICIOUS-EVIDENT` (Exit 20 / BLOCK): Planted canary observed in outbound payload OR >= 2 independent strong signal classes.
  * `SUSPICIOUS` (Exit 10 / REVIEW): Anomalous capabilities observed without explicit licensing.
  * `INCONCLUSIVE` (Exit 10 / REVIEW): Incomplete execution coverage (e.g. setup failed, native module skipped).
  * `BENIGN-CONSISTENT` (Exit 0 / PASS): All observed actions match stated intent within tested coverage.
* **Visual:** Screenshot of HTML Report v1.5 with the "Why This Verdict" explanation box.

---

### Slide 7: Live / Recorded Demonstration
* **Walkthrough:**
  1. Terminal run: `python -m trustlens scan bench/packages/malicious/evil_slug`
  2. Interactive HTML report: Evidence chain (Claim -> Trigger -> File:Line -> Canary ID).
  3. Environment-differential detection on `delayed_slug` (Dev clean, CI malicious).
  4. `demo-all` verification matrix across all benchmark packages.
* **Visual:** Live terminal + browser report.

---

### Slide 8: Evaluation & PS1-Bench Metrics
* **Source:** `reports/eval/results.json` (as of 2026-10-26, fixture evaluation).
* **Metrics Summary:**
  * **Malicious Packages Tested:** 2/2 detected (2/2 on tested variants).
  * **Clean Controls Tested:** 2/2 passed without false alarms.
  * **False-Positive Rate:** FP 0/2 with Wilson 95% CI [0.0, 0.6576].
  * **Median Runtime:** 0.01s per fixture replay (baselines not run).
  * **Honest Footnote:** Datasets are used exclusively for calibration and testing, never for model training.

---

### Slide 9: Competitive Landscape & Novelty

| Feature / Dimension | TrustLens AI | GuardDog 3.2.0 | PipCanary 0.1.1 | Packj (CLI) |
|---|---|---|---|---|
| **Primary Method** | Sandbox + Claims Verification | Static AST / Semgrep rules | Dynamic Sandbox (strace) | Static + Dynamic |
| **Baiting with Canary Secrets** | Yes (SSH, AWS, Tokens) | No | Limited | No |
| **Compares Against README Claims** | Yes (Observed - Claimed) | No | No | No |
| **Environment-Differential (Dev vs CI)** | Yes (Dual-profile matrix) | No | No | No |
| **Startup-Hook Analysis (.pth)** | Yes (Real install diff) | Limited (heuristic) | No | No |
| **Abstention Policy (Coverage Block)** | Yes (`INCONCLUSIVE`) | No (silent pass) | No | No |
| **CI / Code Scanning Output** | Native SARIF 2.1.0 + HTML | GitHub Action (SARIF) | Text output | JSON |

*Footnote:* GuardDog and PipCanary evaluated using pinned public versions. Packj comparison based on published specifications (no AGPL code included).

---

### Slide 10: Limitations & Future Roadmap
* **Known Limitations (Honest Disclosure):**
  * Dynamic analysis only observes paths that actually execute.
  * Blocked network means we observe outbound attempts, not server replies.
  * Staged payloads requiring multi-step server interaction need loopback sinkholing.
* **Roadmap:**
  * Phase 1 (Immediate): Localhost Web UI for one-click package drops.
  * Phase 2: Loopback HTTP sinkhole for staged dropper emulation.
  * Phase 3: Expansion to npm ecosystems.

---

### Backup Slide B1: Pitch Defense & What We Do NOT Claim
* We do not claim to be the "first sandbox tool" (PipCanary and OpenSSF Package Analysis exist).
* We do not claim "zero false positives" or "100% security" (we report Wilson 95% confidence intervals and abstain when unobserved).
* We do **NOT** claim live ML or LLM magic in the verdict path (our verdicts are deterministic, auditable, and offline).

### Backup Slide B2: Verification Commands for Judges
```bash
make demo-all       # Verify all ground truth packages in labels.yaml
make demo-compare   # Generate side-by-side comparison report
python -m pytest tests/e2e -v   # Run full end-to-end regression suite
python scripts/audit_contracts.py  # Verify all JSON schemas
```
