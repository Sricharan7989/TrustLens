"""Dev B: observed minus claimed -> findings -> verdict."""
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
    cutoffs = W.get("severity_cutoffs", {"critical": 12, "high": 7, "medium": 4})
    return "critical" if score >= cutoffs.get("critical", 12) else "high" if score >= cutoffs.get("high", 7) else "medium" if score >= cutoffs.get("medium", 4) else "low" if score > 0 else "info"


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
    e = ev.get("evidence") or {}
    file_name = Path(e['file']).name if e.get('file') else '?'
    where = f"{file_name}:{e.get('line') or '?'}"
    source = claim.get("source") or "metadata"
    src_label = "README" if source == "readme" else source
    quote = claim.get("quote")
    if quote:
        claim_part = f"The {src_label} says «{quote}» ({source});"
    else:
        claim_part = f"No usable claim was found in the {src_label};"
    verb = VERB.get(ev.get("capability"), "did")
    desc = _desc(ev)
    action_part = f"during {ev.get('phase', 'run')} under {ev.get('profile', 'dev')} it {verb} {desc} at {where}"

    canary_part = ""
    canary_ids = ev.get("canary_ids") or []
    if canary_ids:
        where_canary = desc or where
        canary_part = f" and the fake secret {', '.join(canary_ids)} appeared in {where_canary}"

    outcome_part = f". Outcome: {ev.get('outcome', 'unknown')}."
    res = f"{claim_part} {action_part}{canary_part}{outcome_part}"
    if extra:
        res = f"{res} {extra}"
    return res.strip()


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
        canary = canary or any(bool(e.get("canary_hit")) for e in ev_list)
        startup_escalated = any(e["phase"] == "startup" and e["capability"] in ("network", "fs_read_sensitive", "env_secrets") for e in ev_list)
        escalation_mult = W.get("startup_escalation_multiplier", 1.5) if startup_escalated else 1.0
        is_dep = all(str(e.get("attributed_to", "")).startswith("dep:") for e in ev_list)
        dep_mult = W.get("dep_multiplier", 0.7) if (is_dep and not canary) else 1.0

        if signal_class == "info":
            score = 0.0
            sev_label = "info"
        else:
            score = sev[cap] * pw.get(first["phase"], 0.6) * (W["canary_multiplier"] if canary else 1) * (W["env_differential_multiplier"] if diff else 1) * (W["obfuscation_multiplier"] if obf else 1) * escalation_mult * dep_mult
            sev_label = _sev_label(score)

        if startup_escalated and "[Escalated:" not in extra:
            extra = (extra + " [Escalated: executed during interpreter startup before user code].").strip()
        if is_dep and not canary and "[Attributed to dependency" not in extra:
            dep_name = first.get("attributed_to")
            extra = (extra + f" [Attributed to dependency: {dep_name}].").strip()
        findings.append({"id": f"f{len(findings)}", "rule": rule, "title": title, "severity": sev_label, "score": round(score, 2), "capability": cap,
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
    OBF_WORDS = ("base64", "b64decode", "zlib", "decompress", "xor", "chr(", "ord(", "marshal")
    EXEC_WORDS = ("exec", "eval", "compile", "subprocess", "os.system")
    for e in by_cap.get("dynamic_exec", []):
        snippet = str(e["detail"].get("decoded_snippet", "")).lower()
        has_network_or_exec = any(w in snippet for w in NETWORK_WORDS) or any(w in snippet for w in EXEC_WORDS)
        has_obf = any(w in snippet for w in OBF_WORDS)
        is_dep = str(e.get("attributed_to", "")).startswith("dep:")
        claimed_shim = (
            False
            if claims.get("unknown_intent")
            else (_claim_for(claims, "dynamic_exec", e["phase"])["status"] == "claimed"
                  or any(i["intent"] in ("cli_tool", "native_ext") for i in claims.get("intents", [])))
        )
        is_template_shim = "templateshim" in snippet
        is_shim = (is_dep or claimed_shim or is_template_shim) and not (has_network_or_exec or has_obf)
        if is_shim:
            add("decoded_exec", "Dynamic code execution (compatibility/templating shim)", [e], "info", obf=False,
                extra=f'Code snippet: "{snippet[:90]}". Benign shim or template execution.')
        else:
            obf_reasons = []
            if any(w in snippet for w in NETWORK_WORDS):
                obf_reasons.append("touches network/process APIs")
            if has_obf:
                obf_reasons.append("contains obfuscation decoding patterns (base64/zlib/xor/chr)")
            reason_str = " and ".join(obf_reasons) if obf_reasons else "runtime-built execution"
            add("decoded_exec", "Runtime-built code was executed", [e], "decoded_exec", obf=True,
                extra=f'Decoded code: "{snippet[:100]}". Detected: {reason_str}.')

    # R5 environment-differential behaviour
    for cap, s in fingerprint["capability_summary"].items():
        if s["conditional"] and cap not in ("sandbox_probe", "native_code") and sev[cap] >= 3:
            evs = by_cap[cap]
            active_profiles = {e["profile"] for e in evs}
            active_variants = {e["variant"] for e in evs}

            ci_gated = ("ci" in active_profiles) and ("dev" not in active_profiles)
            clock_gated = ("clock+30d" in active_variants) and ("default" not in active_variants)

            if ci_gated or clock_gated:
                gating_factors = []
                if ci_gated:
                    gating_factors.append(f"profile(s) {', '.join(sorted(active_profiles))} (gated from dev)")
                if clock_gated:
                    gating_factors.append(f"variant(s) {', '.join(sorted(active_variants))} (gated from default)")
                gating_str = "; ".join(gating_factors)
                add("env_differential", f"{cap} only appears under some environment profiles/variants", evs, "env_differential", diff=True,
                    extra=f'Seen conditionally under {gating_str}: execution behaviour is gated on the environment.')

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
    done = {f["capability"] for f in findings if f["signal_class"] != "info"}
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
    phases_run = cov.get("phases_run", [])
    profiles_run = cov.get("profiles_run", [])
    variants_run = cov.get("variants_run", ["default"])
    triggers_run = cov.get("triggers_run", [])
    install_completed = cov.get("install_completed", False)
    callables_total = cov.get("callables_total", 0)
    callables_exercised = cov.get("callables_exercised", 0)
    install_note = str(cov.get("install_note", "")).lower()

    run_err = (
        bool(cov.get("run_error"))
        or bool(cov.get("run_timeout"))
        or any(e.get("kind") == "run.error" or "timeout" in str(e.get("detail", {})).lower() for e in events)
        or "timeout" in install_note
    )
    callable_thin = bool(callables_total and (callables_exercised / callables_total < W.get("min_callable_ratio_for_benign", 0.5)))
    thin = (
        not install_completed
        or not phases_run
        or len(profiles_run) < 2
        or callable_thin
        or (run_err and len(classes) < W.get("block_min_independent_signals", 2) and "canary_in_bytes" not in classes)
    )

    if "canary_in_bytes" in classes or len(classes) >= W.get("block_min_independent_signals", 2):
        verdict, action = "MALICIOUS-EVIDENT", "BLOCK"
    elif classes or top >= W.get("suspicious_threshold", 4.0):
        verdict, action = "SUSPICIOUS", "REVIEW"
    elif thin:
        verdict, action = "INCONCLUSIVE", "REVIEW"
    else:
        verdict, action = "BENIGN-CONSISTENT", "PASS"

    if "canary_in_bytes" in classes or len(classes) >= W.get("high_confidence_min_classes", 3):
        confidence = "high"
    elif verdict in ("MALICIOUS-EVIDENT", "SUSPICIOUS"):
        confidence = "medium"
    elif verdict == "INCONCLUSIVE":
        confidence = "low"
    else:
        deep_coverage = (
            len(profiles_run) >= 2
            and ("startup" in phases_run or "fresh_startup" in triggers_run)
            and ("clock+30d" in variants_run)
            and cov.get("strace_layer") is True
        )
        confidence = "high" if deep_coverage else "medium"
    name = fingerprint["package"]["name"]
    if verdict == "MALICIOUS-EVIDENT":
        summary = f"{name}: behaviour contradicts its claims. Independent signals: {', '.join(classes)}."
    elif verdict == "SUSPICIOUS":
        summary = f"{name}: unexplained behaviour found ({', '.join(classes) or 'low-confidence mismatch'}); review before use."
    elif verdict == "INCONCLUSIVE":
        summary = f"{name}: nothing malicious seen, but coverage is too thin to verify claims (see coverage.not_observed)."
    else:
        summary = f"{name}: all observed behaviour is consistent with its stated purpose, within the coverage listed below."

    static_rules = sorted({s.get("rule") for s in fingerprint.get("static_signals", []) if s.get("rule")})
    if static_rules:
        summary += f" Static signals noted: {', '.join(static_rules)}."
        total += len(static_rules) * float(W.get("static_signal_weight", 0.0))
    dep_summary: dict[str, dict] = {}
    for e in events:
        attr = str(e.get("attributed_to") or "")
        if attr.startswith("dep:"):
            dep_name = attr[4:]
            entry = dep_summary.setdefault(dep_name, {
                "name": dep_name,
                "event_count": 0,
                "capabilities": set(),
                "phases": set(),
                "canary_hit": False,
                "findings": [],
            })
            entry["event_count"] += e.get("count", 1)
            entry["capabilities"].add(e["capability"])
            entry["phases"].add(e["phase"])
            if e.get("canary_hit"):
                entry["canary_hit"] = True

    for f in findings:
        for ev_id in f.get("events", []):
            matching_ev = next((e for e in events if e["id"] == ev_id), None)
            if matching_ev:
                attr = str(matching_ev.get("attributed_to") or "")
                if attr.startswith("dep:"):
                    dep_name = attr[4:]
                    if dep_name in dep_summary and f["id"] not in dep_summary[dep_name]["findings"]:
                        dep_summary[dep_name]["findings"].append(f["id"])

    dep_report = {
        dep_name: {
            "name": dep_name,
            "event_count": entry["event_count"],
            "capabilities": sorted(entry["capabilities"]),
            "phases": sorted(entry["phases"]),
            "canary_hit": entry["canary_hit"],
            "findings": sorted(entry["findings"]),
        }
        for dep_name, entry in sorted(dep_summary.items())
    }

    return {"schema_version": "1.0", "package": fingerprint["package"], "verdict": verdict, "action": action, "score": round(total, 2), "confidence": confidence,
            "summary": summary, "findings": sorted(findings, key=lambda f: (-f["score"], f["id"])), "independent_signals": classes, "coverage": cov,
            "claims_summary": {"intents": [i["intent"] for i in claims["intents"]], "claimed_capabilities": sorted({c["capability"] for c in claims["claims"]}),
                               "unknown_intent": claims["unknown_intent"]},
            "dependency_attribution": dep_report}
