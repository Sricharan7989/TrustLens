import { motion } from "framer-motion";
import { IconAlertTriangle, IconNetwork, IconFiles, IconShield } from "./Icons.jsx";

export default function Problem() {
  return (
    <section id="problem" className="section" style={{ background: "#000000" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
        >
          {/* Header Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "var(--space-xl)", alignItems: "center", marginBottom: "var(--space-xl)" }}>
            <div>
              <span className="kicker">The Supply Chain Blindspot</span>
              <h2 style={{ fontSize: "clamp(2.6rem, 5.2vw, 4.4rem)", fontWeight: 900, lineHeight: 1.1, letterSpacing: "-0.04em" }}>
                A package description is a <span className="grad-silver">claim</span> — not proof.
              </h2>
            </div>
            <div>
              <p style={{ color: "var(--color-text-muted)", fontSize: "clamp(1.15rem, 1.6vw, 1.32rem)", lineHeight: 1.7, marginBottom: 16 }}>
                Modern supply chain attacks bypass static analysis with base64 obfuscation, dynamic import hooks, and delayed execution timers. An innocent string formatting library claims simple text transforms, but at runtime executes shell commands and reads SSH keys.
              </p>
              <div style={{ display: "flex", alignItems: "center", gap: 10, fontFamily: "var(--font-mono)", fontSize: "0.88rem", color: "#FFFFFF" }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#FFFFFF", boxShadow: "0 0 8px #FFFFFF" }} />
                <span>Static scanners read code. TrustLens observes runtime execution.</span>
              </div>
            </div>
          </div>

          {/* Metric Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20 }}>
            {[
              {
                stat: "0",
                label: "Network Access Declared",
                sub: "Attempted at runtime",
                desc: "The package declares zero network dependencies in pyproject.toml, yet initiates socket connect() during module import.",
                icon: <IconNetwork size={22} color="#FFFFFF" />,
              },
              {
                stat: "1",
                label: "Sensitive Secret Read",
                sub: "~/.ssh/id_rsa (canary matched)",
                desc: "Traps detect unauthorized reads targeting host credential caches, matching unique cryptographic honeytoken tokens.",
                icon: <IconFiles size={22} color="#FFFFFF" />,
              },
              {
                stat: "3",
                label: "Strong Signal Classes",
                sub: "Triggered simultaneously",
                desc: "Multiple independent signal correlations (canary read + subprocess spawn + egress attempt) combine into a definitive MALICIOUS verdict.",
                icon: <IconAlertTriangle size={22} color="#FFFFFF" />,
              },
            ].map((s, i) => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 25 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.15 }}
                transition={{ duration: 0.7, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] }}
                style={{
                  padding: "36px 32px",
                  borderRadius: "var(--radius-xl)",
                  border: "1px solid rgba(255, 255, 255, 0.14)",
                  background: "linear-gradient(180deg, #101014 0%, #060608 100%)",
                  boxShadow: "0 20px 50px -15px rgba(0,0,0,0.85)",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
                  <div style={{
                    fontSize: "clamp(3.8rem, 6.5vw, 5.5rem)",
                    fontWeight: 900,
                    lineHeight: 1,
                    letterSpacing: "-0.04em",
                    color: "#FFFFFF",
                    textShadow: "0 0 25px rgba(255, 255, 255, 0.3)",
                  }}>
                    {s.stat}
                  </div>
                  <div style={{
                    width: 40,
                    height: 40,
                    borderRadius: 8,
                    background: "rgba(255, 255, 255, 0.08)",
                    border: "1px solid rgba(255, 255, 255, 0.2)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}>
                    {s.icon}
                  </div>
                </div>

                <div style={{ fontSize: "1.25rem", fontWeight: 800, color: "#FFFFFF", marginBottom: 6 }}>
                  {s.label}
                </div>
                <div style={{ fontSize: "0.88rem", color: "var(--color-chrome)", fontFamily: "var(--font-mono)", marginBottom: 14 }}>
                  {s.sub}
                </div>
                <p style={{ fontSize: "0.95rem", color: "var(--color-text-muted)", lineHeight: 1.6 }}>
                  {s.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
      <style>{`
        @media (max-width: 880px) {
          #problem .container > div > div:first-child { grid-template-columns: 1fr !important; }
          #problem .container > div > div:last-child { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  );
}
