# DEMO_SCRIPT (Owner: Dev D) — 5 minutes, one laptop, Wi-Fi may be off

**Before going on stage:** `make setup-dev && make demo && make eval` once; open `reports/demo/evil_slug/report.html`, `reports/demo/delayed_slug/report.html`, `reports/demo/rest_wrapper/report.html`, `reports/eval/heatmap.html` in tabs. Run `bash scripts/check_env.sh` and say which runner you use (live vs recorded fixtures: **say it out loud**). Have a screen recording as backup.

| t | Say / do | Show |
|---|---|---|
| 0:00 | "Your `requirements.txt` is trust you never checked. Attackers hide in install scripts, `.pth` files, CI-only branches." | slide 2 |
| 0:30 | `python -m trustlens scan bench/packages/malicious/evil_slug --runner live` (or fixture) | terminal: BLOCK, exit 20, evidence lines |
| 1:15 | Open `report.html`: README says "turns titles into URL slugs"; during install it read the fake SSH key and sent **our canary token inside an HTTP request** (blocked by sandbox). "That is proof, not a guess." | evidence chain, timeline |
| 2:00 | `delayed_slug`: clean on a laptop, fires only when `CI` is set; base64-decoded `exec`. "Environment-differential execution finds what a single run misses." | dev vs ci columns |
| 3:00 | `rest_wrapper`: network + env token, **PASS** because README claims a REST client. "Claims license behavior: that is how we avoid false alarms." | report + claim quote |
| 3:30 | Unknown/failed install ⇒ `INCONCLUSIVE`. "We abstain instead of bluffing." Show coverage block `not_observed`. | coverage |
| 4:00 | `make eval` heatmap: recall per trigger × gate; FP as `k/n` + CI; baselines GuardDog/PipCanary (as measured, with how-run note). | heatmap, summary.md |
| 4:40 | Limitations + roadmap (npm, sinkhole, native). | slide |
| 5:00 | Q&A. | |

## Hard rules for the demo
* Say "to our knowledge". Never claim "first", "100%", "zero false positives" or "safe".
* Only toy packages run live. If asked about real malware: "tested in a no-network sandbox on a seeded Datadog sample; numbers on slide N" (only if Dev C finished it).
* If live fails: `--runner fixture` and say "recorded run".

## Likely questions
How do you avoid FPs? (claims license + calibrated whitelist + abstention + CI) · What if malware detects the sandbox? (limitations slide, camouflage + differential + sandbox_probe) · Why not an LLM? (offline, reproducible) · How is this different from PipCanary/GuardDog? (see comparison slide, factual) · Does it run on npm? (roadmap).
