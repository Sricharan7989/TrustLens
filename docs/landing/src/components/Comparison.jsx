import { motion } from "framer-motion";
import { IconCheck, IconCross } from "./Icons.jsx";

const rows = [
  {
    feature: "Full Lifecycle Execution Observation",
    trustlens: "Install, startup (.pth), import, call, CLI",
    traditional: "Static AST syntax scan only",
  },
  {
    feature: "Dual Environment Gating (dev vs CI)",
    trustlens: "Both profiles + 30-day clock shift",
    traditional: "Single static pass",
  },
  {
    feature: "Startup Hook & Persistence Detection",
    trustlens: "Diffs site-packages & sitecustomize.py",
    traditional: "Blind to bootstrap persistence",
  },
  {
    feature: "Canary Honeytoken Exfiltration Traps",
    trustlens: "Cryptographic token bytes tracked in I/O",
    traditional: "Heuristic regex pattern matching",
  },
  {
    feature: "README Claims vs. Reality Comparison",
    trustlens: "Mismatch engine with line citations",
    traditional: "Zero intent awareness",
  },
  {
    feature: "Honest Abstention Guarantee",
    trustlens: "INCONCLUSIVE ladder on thin coverage",
    traditional: "False PASS on unexecuted code",
  },
  {
    feature: "Zero-Network Offline Determinism",
    trustlens: "Pure rules, 0 LLM hallucination risk",
    traditional: "Often relies on third-party cloud APIs",
  },
];

export default function Comparison() {
  return (
    <section id="comparison" className="section" style={{ background: "#000000" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Head-to-Head Comparison</span>
          <h2>TrustLens vs. Traditional Scanners</h2>
          <p>
            Static analysis parses text files. TrustLens tests and observes what packages actually execute in an isolated kernel sandbox.
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
            borderRadius: "var(--radius-xl)",
            border: "1px solid rgba(255, 255, 255, 0.18)",
            background: "linear-gradient(180deg, #101014 0%, #060608 100%)",
            overflow: "hidden",
            boxShadow: "0 20px 60px -15px rgba(0,0,0,0.85)",
          }}
        >
          {/* Header Row */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "1.4fr 1.3fr 1fr",
            background: "rgba(255, 255, 255, 0.06)",
            borderBottom: "1px solid rgba(255, 255, 255, 0.12)",
          }}>
            <div style={{ padding: "20px 28px", fontSize: "0.92rem", fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-chrome)" }}>
              Capability / Detection Method
            </div>
            <div style={{ padding: "20px 28px", fontSize: "1.02rem", fontWeight: 800, letterSpacing: "0.04em", color: "#FFFFFF", textAlign: "center", borderLeft: "1px solid rgba(255,255,255,0.08)", background: "rgba(255, 255, 255, 0.1)" }}>
              TrustLens AI
            </div>
            <div style={{ padding: "20px 28px", fontSize: "0.92rem", fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-chrome)", textAlign: "center", borderLeft: "1px solid rgba(255,255,255,0.08)" }}>
              Traditional Scanners
            </div>
          </div>

          {/* Table Data Rows */}
          {rows.map((r, i) => (
            <motion.div
              key={r.feature}
              initial={{ opacity: 0, x: -14 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.5, delay: i * 0.04, ease: [0.16, 1, 0.3, 1] }}
              style={{
                display: "grid",
                gridTemplateColumns: "1.4fr 1.3fr 1fr",
                borderBottom: i < rows.length - 1 ? "1px solid rgba(255, 255, 255, 0.06)" : "none",
                background: i % 2 === 0 ? "transparent" : "rgba(255, 255, 255, 0.02)",
              }}
            >
              <div style={{ padding: "18px 28px", fontSize: "1.02rem", color: "var(--color-text)", fontWeight: 600 }}>
                {r.feature}
              </div>
              <div style={{
                padding: "18px 28px",
                fontSize: "0.95rem",
                fontWeight: 600,
                color: "#FFFFFF",
                textAlign: "center",
                borderLeft: "1px solid rgba(255, 255, 255, 0.06)",
                background: "rgba(255, 255, 255, 0.04)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 8,
              }}>
                <IconCheck size={18} color="#FFFFFF" />
                <span>{r.trustlens}</span>
              </div>
              <div style={{
                padding: "18px 28px",
                fontSize: "0.92rem",
                color: "var(--color-chrome)",
                textAlign: "center",
                borderLeft: "1px solid rgba(255, 255, 255, 0.06)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 8,
              }}>
                <IconCross size={18} color="var(--color-chrome)" />
                <span>{r.traditional}</span>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
      <style>{`
        @media (max-width: 768px) {
          #comparison .container > div:nth-child(2) {
            overflow-x: auto;
          }
        }
      `}</style>
    </section>
  );
}
