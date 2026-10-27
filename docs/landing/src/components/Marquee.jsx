export default function Marquee() {
  const items = [
    "Install-time observation",
    "Import-time observation",
    "File & sensitive-path activity",
    "Network & DNS attempts",
    "Process / subprocess tracking",
    "Behavioral sequence correlation",
    "Declared intent vs. observed behavior",
    "Evidence-backed risk assessment",
    "Honest coverage blocks",
    "Deterministic & offline",
  ];
  const doubled = [...items, ...items];
  return (
    <section style={{ padding: "40px 0", borderTop: "1px solid var(--color-border)", borderBottom: "1px solid var(--color-border)", background: "rgba(10,10,20,0.4)", position: "relative", zIndex: 10, overflow: "hidden" }}>
      <div className="marquee">
        <div className="marquee-track">
          {doubled.map((it, i) => (
            <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 24, padding: "0 32px", fontSize: "1.1rem", fontWeight: 500, color: "var(--color-text-muted)", letterSpacing: "-0.01em" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-text)", boxShadow: "0 0 8px var(--color-text)" }} />
              {it}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
