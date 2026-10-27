import { motion } from "framer-motion";

export default function FinalCTA() {
  return (
    <section id="demo" className="section" style={{
      position: "relative",
      overflow: "hidden",
      minHeight: "70vh",
      display: "flex",
      alignItems: "center",
      background: "radial-gradient(ellipse at 50% 50%, rgba(255, 255, 255, 0.06), transparent 70%)",
      borderTop: "1px solid rgba(255, 255, 255, 0.08)",
    }}>
      {/* Subtle Silver Mesh Orbs */}
      <div style={{ position: "absolute", inset: 0, zIndex: 0, pointerEvents: "none" }}>
        <div style={{
          position: "absolute",
          top: "20%",
          left: "25%",
          width: "45vw",
          height: "45vw",
          borderRadius: "50%",
          filter: "blur(140px)",
          opacity: 0.15,
          background: "radial-gradient(circle, #FFFFFF, transparent 70%)",
          animation: "meshSilver 16s ease-in-out infinite alternate",
        }} />
      </div>

      <style>{`
        @keyframes meshSilver {
          0% { transform: translate(0, 0) scale(1); }
          100% { transform: translate(50px, -30px) scale(1.15); }
        }
      `}</style>

      <div className="container" style={{ position: "relative", zIndex: 10, textAlign: "center" }}>
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        >
          <span className="kicker">Verify Before You Trust</span>
          <h2 style={{
            fontSize: "clamp(2.8rem, 6.5vw, 5.6rem)",
            fontWeight: 900,
            lineHeight: 1.05,
            letterSpacing: "-0.04em",
            marginBottom: 24,
            maxWidth: 960,
            margin: "0 auto 24px auto",
          }}>
            Trust should be earned at <span className="grad-silver">runtime.</span>
          </h2>
          <p style={{
            color: "var(--color-text-muted)",
            maxWidth: 680,
            margin: "0 auto 40px auto",
            fontSize: "clamp(1.18rem, 1.8vw, 1.38rem)",
            lineHeight: 1.65,
          }}>
            Run untrusted packages through the dynamic sandbox and get mathematical evidence before dependencies earn access to your production secrets.
          </p>

          <div style={{ display: "flex", gap: 18, justifyContent: "center", flexWrap: "wrap" }}>
            <a href="#hero" className="btn btn-primary" style={{ padding: "0 44px", height: 58, fontSize: "1.08rem" }}>
              Analyze a Package Now →
            </a>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-outline"
              style={{ padding: "0 40px", height: 58, fontSize: "1.08rem" }}
            >
              View GitHub Repository
            </a>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
