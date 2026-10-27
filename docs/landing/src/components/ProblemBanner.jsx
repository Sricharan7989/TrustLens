import { motion } from "framer-motion";

export default function ProblemBanner() {
  return (
    <section id="problem" className="section">
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.62, ease: [0.22, 1, 0.36, 1] }}
          style={{ maxWidth: 860, margin: "0 auto", background: "linear-gradient(180deg, rgba(255,255,255,0.06), transparent)", border: "1px solid var(--color-border)", borderRadius: "var(--radius-lg)", padding: "var(--space-lg)", textAlign: "left" }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: "var(--space-sm)" }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", border: "1px solid var(--color-border)", background: "var(--color-card)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, color: "var(--color-text-muted)", fontSize: "1.1rem" }}>⚠</div>
            <div>
              <span style={{ color: "var(--color-text-muted)", display: "block", marginBottom: 6, fontSize: "0.8rem", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase" }}>The problem</span>
              <h3 style={{ fontSize: "1.25rem", marginBottom: "var(--space-sm)" }}>A package's description is a claim — not proof.</h3>
              <p style={{ color: "var(--color-text-muted)", margin: 0, fontSize: "1rem" }}>A string utility claims to format text. At runtime it reads your SSH key, contacts an external host, and exfiltrates canary bytes. TrustLens observes the mismatch between claim and behavior — and reports it with evidence.</p>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
