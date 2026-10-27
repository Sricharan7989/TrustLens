import { motion } from "framer-motion";
import { IconBox, IconShield, IconActivity, IconScale, IconFiles } from "./Icons.jsx";

const nodes = [
  { step: "01", label: "Untrusted Package Intake", sub: "Inspects tarball/wheel, pyproject.toml, and extracts claimed README intents.", icon: <IconBox size={24} color="#FFFFFF" /> },
  { step: "02", label: "Bubblewrap Sandbox", sub: "Runs in an unprivileged container with network namespace unshared & canary traps.", icon: <IconShield size={24} color="#FFFFFF" /> },
  { step: "03", label: "Syscall Normalization", sub: "Parses ptrace strace and CPython audit hooks into structured findings.", icon: <IconActivity size={24} color="#FFFFFF" /> },
  { step: "04", label: "Mismatch Engine", sub: "Evaluates Observed Actions minus Declared Intent against deterministic rule ladder.", icon: <IconScale size={24} color="#FFFFFF" />, accent: true },
  { step: "05", label: "Cryptographic Verdict", sub: "Exports SARIF 2.1.0, HTML timeline, and explicit coverage blocks (never 'safe').", icon: <IconFiles size={24} color="#FFFFFF" /> },
];

export default function Diagram() {
  return (
    <section id="system" className="section" style={{ background: "#050507", borderTop: "1px solid rgba(255,255,255,0.08)", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Analysis Architecture</span>
          <h2>From intake to cryptographic proof</h2>
          <p>
            An end-to-end deterministic verification pipeline. Raw kernel events flow into an immutable behavioral fingerprint, which is rigorously checked against claimed package intent.
          </p>
        </motion.div>

        {/* Desktop Pipeline Cards */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          gap: 16,
          margin: "40px auto 0 auto",
        }}>
          {nodes.map((n, i) => (
            <motion.div
              key={n.label}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.6, delay: i * 0.08, ease: [0.16, 1, 0.3, 1] }}
              style={{
                position: "relative",
                padding: "32px 20px",
                borderRadius: "var(--radius-xl)",
                background: n.accent ? "linear-gradient(180deg, #1C1C22 0%, #0D0D10 100%)" : "linear-gradient(180deg, #0F0F12 0%, #060608 100%)",
                border: `1px solid ${n.accent ? "rgba(255, 255, 255, 0.5)" : "rgba(255, 255, 255, 0.12)"}`,
                boxShadow: n.accent ? "0 0 35px rgba(255, 255, 255, 0.15)" : "0 10px 30px -10px rgba(0,0,0,0.8)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                textAlign: "center",
                gap: 12,
                transition: "all 0.3s ease",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = "translateY(-6px)";
                e.currentTarget.style.borderColor = "#FFFFFF";
                e.currentTarget.style.boxShadow = "0 20px 40px -10px rgba(255, 255, 255, 0.2)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "translateY(0)";
                e.currentTarget.style.borderColor = n.accent ? "rgba(255, 255, 255, 0.5)" : "rgba(255, 255, 255, 0.12)";
                e.currentTarget.style.boxShadow = n.accent ? "0 0 35px rgba(255, 255, 255, 0.15)" : "0 10px 30px -10px rgba(0,0,0,0.8)";
              }}
            >
              {/* Step Badge */}
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "0.8rem",
                fontWeight: 800,
                color: n.accent ? "#000000" : "#FFFFFF",
                background: n.accent ? "#FFFFFF" : "rgba(255, 255, 255, 0.08)",
                padding: "4px 12px",
                borderRadius: 9999,
                border: "1px solid rgba(255, 255, 255, 0.2)",
              }}>
                STEP {n.step}
              </span>

              {/* Icon Container */}
              <div style={{
                width: 48,
                height: 48,
                borderRadius: 12,
                background: "rgba(255, 255, 255, 0.06)",
                border: "1px solid rgba(255, 255, 255, 0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "4px 0",
              }}>
                {n.icon}
              </div>

              {/* Title */}
              <h3 style={{ fontSize: "1.15rem", fontWeight: 800, color: "#FFFFFF", letterSpacing: "-0.02em" }}>
                {n.label}
              </h3>

              {/* Description */}
              <p style={{ fontSize: "0.92rem", color: "var(--color-text-muted)", lineHeight: 1.55 }}>
                {n.sub}
              </p>
            </motion.div>
          ))}
        </div>

        {/* Bottom Banner */}
        <div style={{
          marginTop: "40px",
          textAlign: "center",
          fontFamily: "var(--font-mono)",
          fontSize: "0.92rem",
          color: "#FFFFFF",
          background: "rgba(255, 255, 255, 0.04)",
          border: "1px solid rgba(255, 255, 255, 0.14)",
          padding: "14px 24px",
          borderRadius: 9999,
          maxWidth: 780,
          margin: "40px auto 0 auto",
          boxShadow: "0 4px 20px rgba(0, 0, 0, 0.5)",
        }}>
          Deterministic rule-based ladder · 100% offline · Standard exit codes: 0 (PASS), 10 (REVIEW), 20 (BLOCK)
        </div>
      </div>
      <style>{`
        @media (max-width: 1040px) {
          #system .container > div:nth-child(2) {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
        @media (max-width: 640px) {
          #system .container > div:nth-child(2) {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
