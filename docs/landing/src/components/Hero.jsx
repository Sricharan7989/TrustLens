import { useState, lazy, Suspense, useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import SplitText from "./SplitText.jsx";
import ScrambleText from "./ScrambleText.jsx";
import { IconTerminal, IconShield, IconNetwork, IconFiles, IconCpu, IconKey } from "./Icons.jsx";
const Canvas3D = lazy(() => import("./Canvas3D.jsx"));

export default function Hero() {
  const [tab, setTab] = useState("pypi");
  const [copied, setCopied] = useState(false);
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const y = useTransform(scrollYProgress, [0, 1], [0, 160]);
  const opacity = useTransform(scrollYProgress, [0, 0.75], [1, 0]);

  const tabs = {
    pypi: {
      chip: "pypi · string_utils v2.1.0",
      status: "MALICIOUS (Blocked)",
      events: [
        { k: "net.connect", t: "00:12", d: "Attempted TCP connect to 198.51.100.44:443 — isolated & logged", tag: "CRITICAL" },
        { k: "fs.read", t: "00:14", d: "Read sensitive ~/.ssh/id_rsa — honeytoken canary matched", tag: "ALERT" },
        { k: "proc.spawn", t: "00:15", d: "Spawned /bin/sh subprocess executing curl with token bytes", tag: "CRITICAL" },
        { k: "env.read", t: "00:16", d: "Read AWS_SECRET_ACCESS_KEY — honeytoken canary matched", tag: "ALERT" },
      ],
      cmd: "python -m trustlens scan string_utils --offline",
    },
    local: {
      chip: "local · ./safe-tool v1.0.0",
      status: "BENIGN-CONSISTENT",
      events: [
        { k: "build.setup", t: "00:02", d: "setup.py egg_info — standard metadata verification", tag: "VERIFIED" },
        { k: "import.all", t: "00:04", d: "Imported 12 modules — zero undeclared network or file syscalls", tag: "CLEAN" },
        { k: "call.api", t: "00:07", d: "Executed public methods — behavior strictly matches README intent", tag: "CLEAN" },
        { k: "verdict.ok", t: "00:09", d: "100% coverage verified — zero suspicious deviations found", tag: "PASSED" },
      ],
      cmd: "python -m trustlens scan ./my-package --runner bwrap",
    },
  };

  const data = tabs[tab];

  const handleCopy = () => {
    navigator.clipboard.writeText(data.cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section ref={ref} id="hero" style={{ position: "relative", minHeight: "95vh", display: "flex", flexDirection: "column", justifyContent: "center", overflow: "hidden", zIndex: 10, paddingTop: 130, paddingBottom: 70 }}>
      {/* 3D ambient particle background */}
      <motion.div style={{ position: "absolute", inset: 0, zIndex: 0, y, opacity }}>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(ellipse at 50% 30%, rgba(255, 255, 255, 0.08), transparent 70%)" }} />
        <Suspense fallback={null}>
          <Canvas3D />
        </Suspense>
      </motion.div>

      {/* Grid overlay */}
      <div style={{ position: "absolute", inset: 0, zIndex: 1, pointerEvents: "none", opacity: 0.15, backgroundImage: "linear-gradient(rgba(255,255,255,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.08) 1px, transparent 1px)", backgroundSize: "50px 50px", maskImage: "radial-gradient(ellipse at 50% 50%, black 40%, transparent 80%)" }} />

      <div className="container" style={{ position: "relative", zIndex: 10, textAlign: "center" }}>
        {/* Eyebrow Kicker */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          style={{ display: "inline-flex", alignItems: "center", gap: 10, padding: "8px 20px", borderRadius: 9999, border: "1px solid rgba(255, 255, 255, 0.2)", background: "rgba(255, 255, 255, 0.06)", backdropFilter: "blur(12px)", marginBottom: 28, fontSize: "0.88rem", fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", color: "#FFFFFF", boxShadow: "0 0 20px rgba(255, 255, 255, 0.1)" }}
        >
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#FFFFFF", boxShadow: "0 0 10px #FFFFFF" }} />
          <ScrambleText text="BEHAVIOR-FIRST DEPENDENCY SECURITY" delay={0.3} />
        </motion.div>

        {/* Main Headline */}
        <h1 style={{ fontSize: "clamp(3.2rem, 7vw, 6.2rem)", fontWeight: 900, lineHeight: 1.05, letterSpacing: "-0.04em", marginBottom: 24, maxWidth: 1180, margin: "0 auto 24px auto" }}>
          <SplitText text="Know what your" delay={0.2} stagger={0.06} />
          <br />
          <span className="grad-text">
            <SplitText text="dependencies actually do." delay={0.4} stagger={0.06} />
          </span>
        </h1>

        {/* Subtitle Copy */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 0.8, ease: [0.16, 1, 0.3, 1] }}
          style={{ color: "var(--color-text-muted)", fontSize: "clamp(1.18rem, 1.9vw, 1.4rem)", maxWidth: 740, lineHeight: 1.65, margin: "0 auto 40px auto" }}
        >
          Observe install hooks, startup hooks, network attempts, and canary leakage inside an isolated sandbox. Compare runtime telemetry against declared README claims.
        </motion.p>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 1.0, ease: [0.16, 1, 0.3, 1] }}
          style={{ display: "flex", gap: 18, justifyContent: "center", flexWrap: "wrap", marginBottom: 54 }}
        >
          <a href="#report-preview" className="btn btn-primary">
            Explore Live Sample Report →
          </a>
          <a href="#how" className="btn btn-outline">
            See the 5-Step Pipeline
          </a>
        </motion.div>

        {/* Interactive Tabbed Terminal Window */}
        <motion.div
          initial={{ opacity: 0, y: 35 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 1.2, ease: [0.16, 1, 0.3, 1] }}
          style={{ maxWidth: 1040, margin: "0 auto", textAlign: "left" }}
        >
          {/* Tab Selector Buttons */}
          <div style={{ display: "flex", gap: 10, marginBottom: 14, justifyContent: "center" }}>
            {[
              { id: "pypi", label: "Malicious Sample (string_utils)" },
              { id: "local", label: "Clean Control (safe-tool)" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  padding: "10px 24px",
                  fontSize: "0.92rem",
                  fontWeight: 700,
                  letterSpacing: "0.03em",
                  color: tab === t.id ? "#000000" : "var(--color-text-muted)",
                  background: tab === t.id ? "#FFFFFF" : "rgba(255, 255, 255, 0.05)",
                  border: `1px solid ${tab === t.id ? "#FFFFFF" : "rgba(255, 255, 255, 0.12)"}`,
                  boxShadow: tab === t.id ? "0 0 25px rgba(255, 255, 255, 0.3)" : "none",
                  borderRadius: 9999,
                  cursor: "pointer",
                  transition: "all 0.25s ease",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Terminal Card */}
          <div style={{
            background: "linear-gradient(180deg, #0F0F11 0%, #060608 100%)",
            border: "1px solid rgba(255, 255, 255, 0.18)",
            borderRadius: "var(--radius-xl)",
            padding: "30px 34px",
            position: "relative",
            overflow: "hidden",
            boxShadow: "0 30px 80px -20px rgba(0,0,0,0.9), 0 0 40px rgba(255,255,255,0.06)",
          }}>
            {/* Top Accent Line */}
            <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: "linear-gradient(90deg, transparent, #FFFFFF, transparent)", opacity: 0.5 }} />

            {/* Terminal Window Bar */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, paddingBottom: 16, borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
              {/* Traffic Lights */}
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FFFFFF", opacity: 0.4, display: "inline-block" }} />
                <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FFFFFF", opacity: 0.6, display: "inline-block" }} />
                <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FFFFFF", opacity: 0.9, display: "inline-block" }} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--color-text-subtle)", marginLeft: 14 }}>sandbox://isolated-container</span>
              </div>

              {/* Package Chip & Status Pill */}
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.88rem", color: "#FFFFFF", background: "rgba(255, 255, 255, 0.08)", padding: "5px 14px", borderRadius: 8, border: "1px solid rgba(255, 255, 255, 0.16)" }}>
                  {data.chip}
                </span>
                <span style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.85rem",
                  fontWeight: 800,
                  color: "#000000",
                  background: "#FFFFFF",
                  border: "1px solid #FFFFFF",
                  padding: "5px 14px",
                  borderRadius: 8,
                  boxShadow: "0 0 16px rgba(255, 255, 255, 0.3)",
                }}>
                  {data.status}
                </span>
              </div>
            </div>

            {/* Terminal Body: 2 Columns */}
            <div style={{ display: "grid", gridTemplateColumns: "1.3fr 0.9fr", gap: 28 }}>
              {/* Left Column: Live Event Stream */}
              <div>
                <div style={{ fontSize: "0.82rem", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-text-subtle)", marginBottom: 12 }}>
                  Runtime Syscall Telemetry
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {data.events.map((e, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -14 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.08 * i, duration: 0.4 }}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        padding: "12px 16px",
                        borderRadius: 12,
                        background: "rgba(255, 255, 255, 0.03)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        borderLeft: "3px solid #FFFFFF",
                      }}
                    >
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem", color: "var(--color-text-subtle)", minWidth: 44 }}>{e.t}</span>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.88rem", fontWeight: 700, color: "#FFFFFF", minWidth: 92 }}>{e.k}</span>
                      <span style={{ fontSize: "0.95rem", color: "var(--color-text-muted)", flex: 1, lineHeight: 1.4 }}>{e.d}</span>
                    </motion.div>
                  ))}
                </div>
              </div>

              {/* Right Column: Execution Stages */}
              <div>
                <div style={{ fontSize: "0.82rem", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--color-text-subtle)", marginBottom: 12 }}>
                  Execution Phases & Gating
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {[
                    { label: "Install Hook Interception", sub: "setup.py, pyproject.toml", status: "VERIFIED" },
                    { label: "Interpreter Startup Hooks", sub: ".pth diff & sitecustomize.py", status: "VERIFIED" },
                    { label: "Import-All Trigger Matrix", sub: "Dynamic bytecode inspection", status: "TRIPPED" },
                    { label: "Clock-Shift +30 Days", sub: "Time-bomb & delayed activation", status: "TESTED" },
                  ].map((phase, i) => (
                    <div
                      key={phase.label}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "12px 16px",
                        borderRadius: 12,
                        background: "rgba(255, 255, 255, 0.02)",
                        border: "1px solid rgba(255,255,255,0.06)",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <div style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: phase.status === "TRIPPED" ? "#FFFFFF" : "var(--color-chrome)",
                          boxShadow: phase.status === "TRIPPED" ? "0 0 10px #FFFFFF" : "none",
                        }} />
                        <div>
                          <div style={{ fontSize: "0.92rem", fontWeight: 600, color: "var(--color-text)" }}>{phase.label}</div>
                          <div style={{ fontSize: "0.78rem", color: "var(--color-text-subtle)" }}>{phase.sub}</div>
                        </div>
                      </div>
                      <span style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.76rem",
                        fontWeight: 700,
                        padding: "3px 9px",
                        borderRadius: 6,
                        background: "rgba(255, 255, 255, 0.08)",
                        color: "#FFFFFF",
                        border: "1px solid rgba(255, 255, 255, 0.16)",
                      }}>
                        {phase.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Bottom CLI Bar with Copy Button */}
            <div style={{
              marginTop: 24,
              paddingTop: 18,
              borderTop: "1px solid rgba(255,255,255,0.08)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 16,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ color: "#FFFFFF", fontWeight: 700, fontFamily: "var(--font-mono)" }}>$</span>
                <code style={{ fontSize: "0.92rem", color: "#FFFFFF", background: "rgba(255,255,255,0.06)", padding: "6px 14px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.1)" }}>
                  {data.cmd}
                </code>
              </div>
              <button
                onClick={handleCopy}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 18px",
                  borderRadius: 8,
                  background: copied ? "#FFFFFF" : "rgba(255,255,255,0.08)",
                  border: "1px solid rgba(255,255,255,0.2)",
                  color: copied ? "#000000" : "#FFFFFF",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.85rem",
                  fontWeight: 700,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                {copied ? "Copied to Clipboard ✓" : "Copy Command"}
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
