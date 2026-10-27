import { motion } from "framer-motion";

const cards = [
  { icon: "📄", tag: "Install", title: "Install-time & import-time observation", desc: "Records every install hook, .pth and sitecustomize startup hook, and import event — under dev and CI profiles, with a +30-day clock variant.", accent: false },
  { icon: "🌐", tag: "Network", title: "Network & DNS attempts", desc: "Logs DNS lookups, connection attempts, and outbound bytes. Network is always blocked in the sandbox — the attempt itself is the evidence. Canary-in-bytes is detected when tokens appear in outgoing data.", accent: true },
  { icon: "📁", tag: "File system", title: "File & sensitive-path activity", desc: "Tracks reads and writes to sensitive paths (SSH keys, credential files, npmrc) and writes outside the package directory. Paths are normalised from the sandbox fake-HOME layout.", accent: false },
  { icon: "⚙️", tag: "Process", title: "Process / subprocess tracking", desc: "Records every spawned process and its argv, plus dynamic code execution (eval, exec, compile) with decoded snippets where measurable.", accent: false },
  { icon: "🔀", tag: "Comparison", title: "Declared intent vs. observed behavior", desc: "Compares the observed capability summary against claims extracted from the package README and metadata, producing mismatch findings with quoted sources.", accent: false },
  { icon: "📊", tag: "Reporting", title: "Evidence-backed risk assessment", desc: "Produces a demo risk index, verdict (BENIGN-CONSISTENT, SUSPICIOUS, INCONCLUSIVE, MALICIOUS-EVIDENT), evidence chain, and honest coverage block — never \"safe\".", accent: false },
];

export default function CapabilityCards() {
  return (
    <section id="capabilities" className="section">
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.62, ease: [0.22, 1, 0.36, 1] }}
          className="section-head"
        >
          <span className="kicker">Capabilities</span>
          <h2>What the analysis covers</h2>
          <p>Staggered, asymmetric capability panels with one accent card — each describing a distinct observation class.</p>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "var(--space-lg)" }}>
          {cards.map((c, i) => (
            <motion.article
              key={c.title}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.62, delay: (i % 3) * 0.08, ease: [0.22, 1, 0.36, 1] }}
              whileHover={{ y: -4, borderColor: "var(--color-border-hover)", boxShadow: c.accent ? "0 0 40px -12px rgba(104,83,255,0.28)" : "0 20px 50px -14px rgba(0,0,0,0.55)" }}
              style={{
                position: "relative",
                padding: "var(--space-lg)",
                borderRadius: "var(--radius-lg)",
                border: "1px solid var(--color-border)",
                background: c.accent ? "linear-gradient(180deg, rgba(255,255,255,0.08), rgba(16,16,24,0.4))" : "linear-gradient(180deg, var(--color-bg-raised), rgba(16,16,24,0.4))",
                borderColor: c.accent ? "rgba(255,255,255,0.5)" : "var(--color-border)",
                display: "flex",
                flexDirection: "column",
                gap: "var(--space-md)",
                transition: "border-color var(--motion-fast) var(--ease-standard)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "var(--space-sm)" }}>
                <div style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "rgba(255,255,255,0.12)", color: "var(--color-text)", fontSize: "1.35rem", flexShrink: 0 }}>{c.icon}</div>
                <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", padding: "2px 8px", borderRadius: 4, border: "1px solid rgba(255,255,255,0.08)", color: c.accent ? "var(--color-text)" : "var(--color-text-subtle)", background: c.accent ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.2)" }}>{c.tag}</span>
              </div>
              <h4 style={{ fontSize: "1.05rem", margin: 0 }}>{c.title}</h4>
              <p style={{ color: "var(--color-text-muted)", fontSize: "0.9rem", lineHeight: 1.6, margin: 0 }}>{c.desc}</p>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
