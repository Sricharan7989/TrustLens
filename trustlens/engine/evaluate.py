"""Dev B: observed minus claimed -> findings -> verdict. STUB-LEVEL v0 that already produces verdicts on the fixtures.

Rules (docs/CONTRACTS.md 3.3): hard rules canary read + network; unclaimed install-phase network; decoded exec;
env-differential behaviour; startup hook; persistence. MALICIOUS-EVIDENT needs >= 2 independent strong signal classes
or a canary inside outgoing bytes. INCONCLUSIVE when coverage is too thin to call a package benign.
TODO(Dev B): per-rule tests, explanation polish, dependency attribution, version-diff hook, weights calibration with C.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from trustlens.contracts import load_capabilities

W = yaml.safe_load((Path(__file__).parent / "weights.yaml").read_text())
NETWORK_WORDS = ("socket", "urllib", "requests", "http", "connect", "subprocess", "os.system", "curl", "wget")
VERB = {"fs_read_sensitive": "read the sensitive file", "env_secrets": "read the secret-looking environment variable", "network": "attempted network access to",
        "dynamic_exec": "executed runtime-built code", "subprocess": "spawned the process", "persistence": "wrote the persistence file",
        "startup_hook": "installed an interpreter startup hook", "fs_write_outside_pkg": "wrote outside the package to", "sandbox_probe": "probed its environment via",
        "native_code": "loaded native code", "install_hook": "ran an install hook", "download_exec": "wrote then executed"}


def _sev_label(score: float) -> str:
    return "critical" if score >= 12 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"


def _desc(ev: dict) -> str:
    d = ev["detail"]
    return str(d.get("path") or d.get("name") or d.get("dest") or d.get("host") or d.get("url") or d.get("decoded_snippet") or d.get("argv") or d.get("file") or "")[:90]


def _claim_for(claims: dict, cap: str, phase: str) -> dict:
    if claims.get("unknown_intent"):
        return {"status": "unknown_intent", "quote": None, "source": None}
    for c in claims["claims"]:
        if c["capability"] == cap and phase in c.get("phases_allowed", ["import", "call", "cli"]):
            return {"status": "claimed", "quote": c["quote"], "source": c["source"]}
    q = (claims["intents"] or [{}])[0]
    return {"status": "not_claimed", "quote": q.get("quote"), "source": q.get("source")}


def _explain(rule: str, ev: dict, claim: dict, extra: str = "") -> str:
    e = ev["evidence"]
    where = f"{Path(e['file']).name if e.get('file') else '?'}:{e.get('line') or '?'}"
    claim_txt = (f'The README says: "{claim["quote"]}"' + (" (this licenses the behaviour)." if claim["status"] == "claimed" else " (nothing there licenses it)."))\
        if claim.get("quote") else "No usable claim was found in the README/metadata, so no discount was applied."
    return (f'During {ev["phase"]} ({ev["trigger"]}, profile {ev["profile"]}), {where} {VERB.get(ev["capability"], "did")} {_desc(ev)}. '
            f'{claim_txt} Outcome: {ev["outcome"]}. {extra}').strip()


def evaluate(fingerprint: dict, claims: dict) -> dict:
    caps = load_capabilities()
    sev = {k: v["severity"] for k, v in caps["capabilities"].items()} | W.get("severity_override", {})
    pw = caps["phase_weight"]
    events = fingerprint["events"]
    findings: list[dict] = []

    def add(rule, title, ev_list, signal_class, *, canary=False, diff=False, obf=False, force_claim=None, extra=""):
        first = ev_list[0]
        cap = first["capability"]
        claim = force_claim or _claim_for(claims, cap, first["phase"])
        startup_escalated = any(e["phase"] == "startup" and e["capability"] in ("network", "fs_read_sensitive", "env_secrets") for e in ev_list)
        escalation_mult = W.get("startup_escalation_multiplier", 1.5) if startup_escalated else 1.0
        score = sev[cap] * pw.get(first["phase"], 0.6) * (W["canary_multiplier"] if canary else 1) * (W["env_differential_multiplier"] if diff else 1) * (W["obfuscation_multiplier"] if obf else 1) * escalation_mult
        if startup_escalated and "[Escalated:" not in extra:
            extra = (extra + " [Escalated: executed during interpreter startup before user code].").strip()
        findings.append({"id": f"f{len(findings)}", "rule": rule, "title": title, "severity": _sev_label(score), "score": round(score, 2), "capability": cap,
                         "phases": sorted({e["phase"] for e in ev_list}), "profiles": sorted({e["profile"] for e in ev_list}), "env_differential": diff,
                         "canary_hit": canary, "signal_class": signal_class, "claim": claim, "events": [e["id"] for e in ev_list],
                         "evidence": [{"event_id": e["id"], "file": e["evidence"].get("file"), "line": e["evidence"].get("line"), "phase": e["phase"],
                                       "profile": e["profile"], "outcome": e["outcome"], "detail": e["detail"]} for e in ev_list[:6]],
                         "explanation": _explain(rule, first, claim, extra)})

    by_cap = {}
    for e in events:
        by_cap.setdefault(e["capability"], []).append(e)
    nets = by_cap.get("network", [])
    # R1 canary access followed by network attempt (same profile)
    for e in by_cap.get("fs_read_sensitive", []) + by_cap.get("env_secrets", []):
        if e["canary_hit"] and any(n["profile"] == e["profile"] and n["seq"] > e["seq"] for n in nets):
            n = next(n for n in nets if n["profile"] == e["profile"] and n["seq"] > e["seq"])
            add("canary_read_then_network", "Fake secret read, then network attempt", [e, n], "canary_access", canary=True, force_claim=_claim_for(claims, e["capability"], e["phase"]),
                extra=f'Then {n["phase"]}-phase network attempt to {_desc(n)} followed. Canary(ies): {", ".join(e["canary_ids"])}.')
            break
    # R2 canary content inside outgoing bytes = proof
    for n in nets:
        if n["detail"].get("canary_in_bytes"):
            add("canary_in_outgoing_bytes", "Fake secret content found inside an outgoing request", [n], "canary_in_bytes", canary=True,
                extra=f'The request carried canary token(s): {", ".join(n["canary_ids"])}.')
            break
    # R3 unclaimed network (one finding per phase)
    for ph in ("install", "startup", "import", "call", "cli"):
        un = [n for n in nets if n["phase"] == ph and _claim_for(claims, "network", ph)["status"] != "claimed"]
        if un:
            add("network_unclaimed", f"Network access in {ph} phase not licensed by the package's claims", un, "network_unclaimed")
    # R4 decoded/dynamic exec
    for e in by_cap.get("dynamic_exec", []):
        snippet = str(e["detail"].get("decoded_snippet", "")).lower()
        add("decoded_exec", "Runtime-built code was executed", [e], "decoded_exec", obf=True,
            extra=f'Decoded code: "{snippet[:100]}".' + (" It touches network/process APIs." if any(w in snippet for w in NETWORK_WORDS) else ""))
        break
    # R5 environment-differential behaviour
    for cap, s in fingerprint["capability_summary"].items():
        if s["conditional"] and cap not in ("sandbox_probe", "native_code") and sev[cap] >= 3:
            evs = by_cap[cap]
            add("env_differential", f"{cap} only appears under some environment profiles ({', '.join(s['profiles'])})", evs, "env_differential", diff=True,
                extra=f'Seen only in profile(s) {", ".join(s["profiles"])} of {", ".join(fingerprint["coverage"]["profiles_run"])}: behaviour gated on the environment.')

    # R6 startup hook
    if by_cap.get("startup_hook"):
        evs = by_cap["startup_hook"]
        code_exec_evs = [e for e in evs if e["detail"].get("executes_code", True)]
        path_only_evs = [e for e in evs if not e["detail"].get("executes_code", True)]
        if code_exec_evs:
            first = code_exec_evs[0]
            d = first["detail"]
            f_name = d.get("file") or first["evidence"].get("file") or "startup hook"
            l_no = first["evidence"].get("line") or 1
            l_txt = d.get("line_text") or ""
            extra = f"File: {f_name}:{l_no}. Executes code on startup: '{l_txt}'."
            startup_sensitive = [e for e in events if e["phase"] == "startup" and e["capability"] in ("network", "fs_read_sensitive", "env_secrets")]
            if startup_sensitive:
                caps_seen = sorted({e["capability"] for e in startup_sensitive})
                extra += f" Hook actively triggered during startup with sensitive capability: {', '.join(caps_seen)}."
            add("startup_hook", "Interpreter startup hook with executable code detected", code_exec_evs, "startup_hook", extra=extra)
        if path_only_evs:
            first = path_only_evs[0]
            d = first["detail"]
            f_name = d.get("file") or first["evidence"].get("file") or "startup.pth"
            extra = f"Path-only entry in {f_name}: '{d.get('line_text', '')}'. Plain directory entry without code execution."
            add("startup_hook", "Plain path entry in .pth file (info)", path_only_evs, "info", extra=extra)

    # R7 persistence
    if by_cap.get("persistence"):
        evs = by_cap["persistence"]
        paths = sorted({e["detail"].get("path") for e in evs if e["detail"].get("path")})
        extra = f"Persistence path(s) written: {', '.join(paths)}. Ensures execution outside package lifecycle."
        add("persistence", "Persistence mechanism installed outside package lifecycle", evs, "persistence", extra=extra)

    # R8 download_exec (dropper lineage)
    if by_cap.get("download_exec"):
        evs = by_cap["download_exec"]
        targets = sorted({str(e["detail"].get("dropped_file") or e["detail"].get("argv") or e["detail"].get("path")) for e in evs if e["detail"].get("dropped_file") or e["detail"].get("argv") or e["detail"].get("path")})
        extra = f"Dropper lineage: written file subsequently executed: {', '.join(targets)}."
        add("download_exec", "Downloaded or written file executed (dropper lineage)", evs, "dropper", extra=extra)

    # R9 other unclaimed capabilities (weak)
    done = {f["capability"] for f in findings}
    for cap in ("fs_read_sensitive", "env_secrets", "subprocess", "fs_write_outside_pkg"):
        evs = [e for e in by_cap.get(cap, []) if _claim_for(claims, cap, e["phase"])["status"] != "claimed"]
        if evs and cap not in done:
            add("capability_not_claimed", f"{cap} observed but not claimed", evs, "mismatch_other")
    for e in by_cap.get("sandbox_probe", [])[:1]:
        add("sandbox_probe", "Package inspects whether it is being watched", [e], "sandbox_probe", force_claim=_claim_for(claims, "sandbox_probe", e["phase"]))

    strong = [c for c in W["strong_signal_classes"]]
    classes = sorted({f["signal_class"] for f in findings if f["signal_class"] in strong})
    total = sum(f["score"] for f in findings)
    top = max([f["score"] for f in findings], default=0)
    cov = fingerprint["coverage"]
    thin = (not cov["install_completed"] or "import" not in cov["phases_run"] or len(cov["profiles_run"]) < 2
            or (cov["callables_total"] and cov["callables_exercised"] / cov["callables_total"] < W["min_callable_ratio_for_benign"]))
    if "canary_in_bytes" in classes or len(classes) >= W["block_min_independent_signals"]:
        verdict, action = "MALICIOUS-EVIDENT", "BLOCK"
    elif classes or top >= W["suspicious_threshold"]:
        verdict, action = "SUSPICIOUS", "REVIEW"
    elif thin:
        verdict, action = "INCONCLUSIVE", "REVIEW"
    else:
        verdict, action = "BENIGN-CONSISTENT", "PASS"
    confidence = "high" if "canary_in_bytes" in classes or len(classes) >= 3 else "medium" if verdict in ("MALICIOUS-EVIDENT", "SUSPICIOUS") or not thin else "low"
    name = fingerprint["package"]["name"]
    if verdict == "MALICIOUS-EVIDENT":
        summary = f"{name}: behaviour contradicts its claims. Independent signals: {', '.join(classes)}."
    elif verdict == "SUSPICIOUS":
        summary = f"{name}: unexplained behaviour found ({', '.join(classes) or 'low-confidence mismatch'}); review before use."
    elif verdict == "INCONCLUSIVE":
        summary = f"{name}: nothing malicious seen, but coverage is too thin to call it safe (see coverage.not_observed)."
    else:
        summary = f"{name}: all observed behaviour is consistent with its stated purpose, within the coverage listed below."
    return {"schema_version": "1.0", "package": fingerprint["package"], "verdict": verdict, "action": action, "score": round(total, 2), "confidence": confidence,
            "summary": summary, "findings": sorted(findings, key=lambda f: -f["score"]), "independent_signals": classes, "coverage": cov,
            "claims_summary": {"intents": [i["intent"] for i in claims["intents"]], "claimed_capabilities": sorted({c["capability"] for c in claims["claims"]}),
                               "unknown_intent": claims["unknown_intent"]}}
