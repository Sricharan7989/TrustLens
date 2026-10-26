# LIMITATIONS (Owner: Dev D; every dev appends what they discover; the deck's limitations slide is generated from this)

Written to be shown to judges. Update with real facts; delete a line only when it is truly fixed and tested.

## Known (design-level)
1. **Dynamic analysis only sees what runs.** Code gated on conditions we did not simulate (specific hostname/user/IP, date beyond +30 days, random trigger, user interaction, a particular argument) is not observed → we say `INCONCLUSIVE`/coverage, never "clean".
2. **Network is blocked, so we see the *attempt*, not the response.** Staged payloads that need a server reply (download-then-exec) show as a blocked download; the second stage is invisible. (Stretch: loopback sinkhole.)
3. **Native code (C extensions) is a black box** without the strace layer, and with it only syscalls. Reported in `coverage.native_skipped`.
4. **Sandbox-aware malware** can detect our environment (camouflage reduces, not eliminates). We log `sandbox_probe` events but a patient package can just sleep/exit.
5. **Claims are extracted by keyword rules**; READMEs that are empty, in another language, or deliberately vague map to *unknown intent* (we license nothing and say so). A README is attacker-controlled: we only ever use it to *license* behavior narrowly, and a lying README plus malicious code still triggers canary rules.
6. **Dependencies:** v0 analyses the target package only; its dependency tree is attributed (`dep:<name>`) but not individually judged.
7. **Python only** (PyPI sdists/wheels). npm is roadmap.
8. Dummy-argument call-all cannot reach code behind real credentials/complex objects: `callables_exercised/total` is reported.

## Known (v0 implementation; remove as fixed)
* Install phase runs `setup.py egg_info` (not a real `pip install`) → wheel/`.pth` startup hooks not exercised until Dev A P0 lands. Synthetic fixture `_synthetic_pth_startup` shows the intended output.
* No strace layer yet; clock+30d, CLI and fresh-startup triggers not run (`run_meta.coverage.not_observed` lists them).
* PS1-Bench is small and *ours*: planted toys test the mechanism, not the real-world detection rate. Report externally sampled results separately.
* PipCanary baseline needs `strace`; if absent it is "not run". GuardDog is run with 3 network-dependent rules excluded (offline).
* QUT-DV25 / OSPtrack column formats unverified until Dev C opens the files.
* FP rate on N clean packages: we report `k/N` with a Wilson 95% CI (e.g. 0/15 ⇒ upper bound ≈ 20%). That is not "zero false positives".

## Not claimed
See AGENTS.md §9.
