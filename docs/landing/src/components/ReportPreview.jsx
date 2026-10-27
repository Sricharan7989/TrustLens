import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";

export default function ReportPreview() {
  const [rt, setRt] = useState("events");
  const [score, setScore] = useState(0);
  const [started, setStarted] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started) {
          setStarted(true);
          let start = performance.now();
          const tick = (now) => {
            const p = Math.min((now - start) / 900, 1);
            const eased = 1 - Math.pow(1 - p, 4);
            setScore(Math.round(eased * 72));
            if (p < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        }
      },
      { threshold: 0.15 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [started]);

  const copy = async (text, btn) => {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {}
    const before = btn.textContent;
    btn.textContent = ok ? "Copied ✓" : "Failed";
    btn.style.color = ok ? "#FFFFFF" : "var(--color-chrome)";
    setTimeout(() => { btn.textContent = before; btn.style.color = ""; }, 1500);
  };

  const events = [
    { chip: "NET", kind: "net.connect", text: "Attempted socket connect to 198.51.100.44:443 — intercepted by network sinkhole. Zero network capabilities declared in pyproject.toml." },
    { chip: "FS", kind: "fs.read", text: "Read sensitive path ~/.ssh/id_rsa — honeytoken canary matched. Not claimed in README." },
    { chip: "PROC", kind: "proc.spawn", text: "Spawned /bin/sh subprocess executing curl to exfiltrate canary bytes — intercepted and blocked by egress namespace." },
    { chip: "ENV", kind: "env.read", text: "Read environment variable AWS_SECRET_ACCESS_KEY — canary matched. No declared need for cloud credentials." },
  ];

  return (
    <section id="report-preview" className="section" ref={ref} style={{ background: "#050507", borderTop: "1px solid rgba(255,255,255,0.08)", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Report Explorer</span>
          <h2>Evidence-backed findings, in plain English</h2>
          <p>
            Interactive report preview for <code style={{ color: "#FFFFFF" }}>string_utils v2.1.0</code> — every finding links directly to the kernel sequence number, file location, and exact README citation.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          style={{
            maxWidth: 1040,
            margin: "0 auto",
            background: "linear-gradient(180deg, #101014 0%, #060608 100%)",
            border: "1px solid rgba(255, 255, 255, 0.18)",
            borderRadius: "var(--radius-xl)",
            padding: "40px",
            boxShadow: "0 30px 80px -20px rgba(0,0,0,0.9), 0 0 40px rgba(255,255,255,0.05)",
          }}
        >
          {/* Top Score Banner */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: "36px",
            alignItems: "center",
            paddingBottom: "32px",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
            marginBottom: "30px",
          }}>
            <div style={{ textAlign: "center", paddingRight: "16px" }}>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "1.05rem",
                fontWeight: 900,
                padding: "8px 20px",
                borderRadius: 9999,
                color: "#000000",
                background: "#FFFFFF",
                boxShadow: "0 0 25px rgba(255, 255, 255, 0.4)",
                letterSpacing: "0.06em",
                display: "inline-block",
                marginBottom: 12,
              }}>
                MALICIOUS-EVIDENT
              </div>
              <div style={{ fontSize: "0.88rem", color: "var(--color-chrome)", fontFamily: "var(--font-mono)" }}>
                Exit Code 20 (CI Block)
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <span style={{ fontSize: "0.95rem", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-text-muted)" }}>
                  Composite Risk Index
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "2.8rem", fontWeight: 900, color: "#FFFFFF" }}>
                  {score}<span style={{ fontSize: "1.3rem", color: "var(--color-text-subtle)" }}>/100</span>
                </span>
              </div>

              {/* Score Bar */}
              <div style={{ height: 8, borderRadius: 4, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${score}%` }}
                  transition={{ duration: 0.3 }}
                  style={{ height: "100%", background: "linear-gradient(90deg, #666666, #FFFFFF)", borderRadius: 4, boxShadow: "0 0 16px rgba(255,255,255,0.5)" }}
                />
              </div>

              <div style={{ display: "flex", gap: 24, flexWrap: "wrap", marginTop: 6, fontFamily: "var(--font-mono)", fontSize: "0.92rem", color: "var(--color-text-muted)" }}>
                <span>Confidence: <strong style={{ color: "#FFFFFF" }}>0.94</strong></span>
                <span>Coverage: <strong style={{ color: "#FFFFFF" }}>4 / 4 phases observed</strong></span>
                <span>Attribution: <strong style={{ color: "#FFFFFF" }}>Package Root (pkg)</strong></span>
              </div>
            </div>
          </div>

          {/* Report Tab Selectors */}
          <div style={{ display: "flex", gap: 10, borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: 12, marginBottom: 24 }}>
            {[
              { id: "events", label: "Raw Syscall Telemetry" },
              { id: "evidence", label: "Mismatch Evidence Chain" },
              { id: "summary", label: "Executive Verdict Summary" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setRt(t.id)}
                style={{
                  padding: "10px 22px",
                  fontSize: "0.92rem",
                  fontWeight: 700,
                  letterSpacing: "0.02em",
                  color: rt === t.id ? "#000000" : "var(--color-text-muted)",
                  border: "none",
                  background: rt === t.id ? "#FFFFFF" : "transparent",
                  borderRadius: 8,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab Content Panes */}
          <div style={{ minHeight: 250 }}>
            {rt === "events" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {events.map((e, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -14 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05, duration: 0.35 }}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 16,
                      padding: "16px 20px",
                      borderRadius: "var(--radius-md)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      background: "rgba(255,255,255,0.03)",
                      fontSize: "1.02rem",
                      lineHeight: 1.6,
                    }}
                  >
                    <span style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.82rem",
                      fontWeight: 800,
                      padding: "4px 10px",
                      borderRadius: 6,
                      border: "1px solid rgba(255,255,255,0.25)",
                      color: "#FFFFFF",
                      background: "rgba(255,255,255,0.1)",
                      flexShrink: 0,
                    }}>
                      {e.chip}
                    </span>
                    <div style={{ color: "var(--color-silver)", flex: 1 }}>{e.text}</div>
                    <button
                      onClick={(ev) => copy(`${e.kind} — ${e.text}`, ev.currentTarget)}
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.82rem",
                        padding: "6px 14px",
                        borderRadius: 6,
                        border: "1px solid rgba(255,255,255,0.18)",
                        color: "#FFFFFF",
                        background: "rgba(255,255,255,0.06)",
                        cursor: "pointer",
                        flexShrink: 0,
                        transition: "all 0.2s",
                      }}
                    >
                      Copy
                    </button>
                  </motion.div>
                ))}
              </motion.div>
            )}

            {rt === "evidence" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {[
                  {
                    rule: "canary_read_then_network",
                    sev: "CRITICAL",
                    desc: "Package metadata claims 'Pure Python formatting utility'. Process read honeytoken ~/.ssh/id_rsa at import phase and immediately attempted TCP connect to 198.51.100.44:443. Evidence chain verified across dev and ci profiles.",
                  },
                  {
                    rule: "network_unclaimed",
                    sev: "HIGH",
                    desc: "Outbound socket connect attempted with 0 network capabilities declared in pyproject.toml or README.md.",
                  },
                  {
                    rule: "subprocess_unlicensed",
                    sev: "HIGH",
                    desc: "Spawned /bin/sh to execute curl without CLI entry point or console script justification in metadata.",
                  },
                ].map((f) => (
                  <div
                    key={f.rule}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 16,
                      padding: "16px 20px",
                      borderRadius: "var(--radius-md)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      background: "rgba(255,255,255,0.03)",
                      fontSize: "1.02rem",
                      lineHeight: 1.6,
                    }}
                  >
                    <span style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.82rem",
                      fontWeight: 800,
                      padding: "4px 10px",
                      borderRadius: 6,
                      border: "1px solid #FFFFFF",
                      color: "#000000",
                      background: "#FFFFFF",
                      flexShrink: 0,
                    }}>
                      {f.sev}
                    </span>
                    <div style={{ color: "var(--color-text-muted)", flex: 1 }}>
                      <strong style={{ color: "#FFFFFF" }}>{f.rule}</strong> — {f.desc}
                    </div>
                    <button
                      onClick={(ev) => copy(`Finding: ${f.rule} (${f.sev})\n${f.desc}`, ev.currentTarget)}
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.82rem",
                        padding: "6px 14px",
                        borderRadius: 6,
                        border: "1px solid rgba(255,255,255,0.18)",
                        color: "#FFFFFF",
                        background: "rgba(255,255,255,0.06)",
                        cursor: "pointer",
                        flexShrink: 0,
                      }}
                    >
                      Copy
                    </button>
                  </div>
                ))}
              </motion.div>
            )}

            {rt === "summary" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} style={{
                padding: "24px 28px",
                borderRadius: "var(--radius-md)",
                border: "1px solid rgba(255, 255, 255, 0.2)",
                background: "rgba(255, 255, 255, 0.04)",
                fontSize: "1.08rem",
                lineHeight: 1.7,
                color: "#FFFFFF",
              }}>
                <div style={{ fontWeight: 800, fontSize: "1.25rem", color: "#FFFFFF", marginBottom: 8 }}>
                  VERDICT: MALICIOUS-EVIDENT (Block Recommended)
                </div>
                <p style={{ color: "var(--color-text-muted)", marginBottom: 16 }}>
                  Execution revealed multiple unadvertised exfiltration attempts. Honeytoken credentials were read during module import and staged for outbound HTTP transmission.
                </p>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.92rem", color: "var(--color-chrome)" }}>
                  Coverage: install (pass), startup (pass), import (pass), call (pass). Coverage sufficiency satisfied across all 4 phases.
                </div>
              </motion.div>
            )}
          </div>

          {/* Bottom Export Actions */}
          <div style={{ display: "flex", gap: 16, justifyContent: "center", paddingTop: 26, borderTop: "1px solid rgba(255,255,255,0.08)", marginTop: 20 }}>
            <button
              onClick={(e) => copy('{"verdict": "MALICIOUS-EVIDENT", "risk_score": 72, "confidence": 0.94}', e.currentTarget)}
              className="btn btn-outline"
              style={{ height: 46, fontSize: "0.92rem" }}
            >
              Copy JSON Verdict
            </button>
            <button
              onClick={(e) => copy('{"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"}', e.currentTarget)}
              className="btn btn-outline"
              style={{ height: 46, fontSize: "0.92rem" }}
            >
              Export SARIF 2.1.0
            </button>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
