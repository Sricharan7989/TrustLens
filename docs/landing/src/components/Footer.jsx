export default function Footer() {
  return (
    <footer style={{ padding: "64px 0 32px", borderTop: "1px solid rgba(255, 255, 255, 0.12)", background: "#000000" }}>
      <div className="container">
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr", gap: 32, marginBottom: 48 }}>
          <div>
            <a href="#" style={{ display: "inline-flex", alignItems: "center", gap: 10, fontWeight: 800, fontSize: "1.1rem", color: "#FFFFFF", marginBottom: 16 }}>
              <span style={{ width: 28, height: 28, borderRadius: 6, background: "#FFFFFF", display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" fill="#000000"><rect width="16" height="16" x="4" y="4" rx="4" /><path d="M10 10h4v4h-4z" fill="#FFFFFF" /></svg>
              </span>
              TrustLens
            </a>
            <p style={{ color: "var(--color-text-subtle)", fontSize: "0.9rem", lineHeight: 1.65, maxWidth: 360 }}>
              PS1 "Trust Nothing: Provenance for Your Own Dependencies" — behavior-first dependency security for Python packages. Rule-based, deterministic, 100% offline.
            </p>
          </div>
          {[
            ["Product", ["Overview", "Capabilities", "Report Preview", "How It Works"]],
            ["Resources", ["Documentation", "GitHub", "Contracts", "AGENTS.md"]],
            ["Legal", ["MIT License", "Quarantine Policy", "Do-Not-Claim List"]],
          ].map(([title, links]) => (
            <div key={title}>
              <div style={{ fontSize: "0.78rem", fontWeight: 800, letterSpacing: "0.14em", textTransform: "uppercase", color: "#FFFFFF", marginBottom: 16 }}>{title}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {links.map((l) => (
                  <a key={l} href="#" style={{ color: "var(--color-text-muted)", fontSize: "0.92rem", transition: "color 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.color = "#FFFFFF"} onMouseLeave={(e) => e.currentTarget.style.color = "var(--color-text-muted)"}>{l}</a>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div style={{ paddingTop: 24, borderTop: "1px solid rgba(255, 255, 255, 0.08)", display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 16, fontSize: "0.82rem", color: "var(--color-text-subtle)" }}>
          <span>© 2026 TrustLens AI · MIT License</span>
          <span style={{ fontFamily: "var(--font-mono)" }}>Sample results are illustrative demo data. Live scans run via <code style={{ color: "#FFFFFF" }}>make demo</code>.</span>
        </div>
      </div>
      <style>{`@media (max-width: 768px) { footer .container > div:first-child { grid-template-columns: 1fr !important; } }`}</style>
    </footer>
  );
}
