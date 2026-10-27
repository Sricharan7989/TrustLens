import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

export default function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    document.body.style.overflow = menuOpen ? "hidden" : "";
    const onKey = (e) => { if (e.key === "Escape") setMenuOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  const links = [
    ["#hero", "Overview"],
    ["#trust", "Telemetry"],
    ["#problem", "The Problem"],
    ["#system", "Pipeline"],
    ["#capabilities", "Capabilities"],
    ["#how", "Process"],
    ["#report-preview", "Report"],
    ["#comparison", "Comparison"],
    ["#faq", "FAQ"],
  ];

  return (
    <>
      <motion.header
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 100,
          display: "flex",
          justifyContent: "center",
          padding: "18px 24px 0",
          pointerEvents: "none",
        }}
      >
        <div
          style={{
            pointerEvents: "auto",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 20,
            width: "100%",
            maxWidth: 1260,
            padding: "10px 24px",
            borderRadius: 9999,
            background: scrolled ? "rgba(10, 10, 12, 0.88)" : "rgba(12, 12, 14, 0.6)",
            backdropFilter: "blur(24px)",
            WebkitBackdropFilter: "blur(24px)",
            border: "1px solid rgba(255, 255, 255, 0.16)",
            boxShadow: scrolled ? "0 10px 40px rgba(0,0,0,0.8), 0 0 25px rgba(255,255,255,0.06)" : "0 4px 20px rgba(0,0,0,0.4)",
            transition: "all 0.3s ease",
          }}
        >
          {/* Logo */}
          <a href="#" style={{ display: "inline-flex", alignItems: "center", gap: 10, fontWeight: 800, fontSize: "1.1rem", color: "#FFFFFF", textDecoration: "none" }}>
            <span style={{
              width: 30,
              height: 30,
              borderRadius: 7,
              background: "#FFFFFF",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 16px rgba(255, 255, 255, 0.3)",
            }}>
              <svg width="15" height="15" viewBox="0 0 24 24" aria-hidden="true" fill="#000000">
                <rect width="16" height="16" x="4" y="4" rx="4" />
                <path d="M10 10h4v4h-4z" fill="#FFFFFF" />
              </svg>
            </span>
            <span>TrustLens</span>
          </a>

          {/* Navigation Links */}
          <nav style={{ display: "flex", gap: 4, alignItems: "center" }} className="nav-desktop">
            {links.map(([href, label]) => (
              <a
                key={href}
                href={href}
                style={{
                  padding: "8px 14px",
                  fontSize: "0.9rem",
                  fontWeight: 600,
                  color: "var(--color-text-muted)",
                  borderRadius: 9999,
                  transition: "all 0.2s ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#FFFFFF";
                  e.currentTarget.style.background = "rgba(255, 255, 255, 0.08)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "var(--color-text-muted)";
                  e.currentTarget.style.background = "transparent";
                }}
              >
                {label}
              </a>
            ))}
          </nav>

          {/* CTA Action */}
          <a
            href="#report-preview"
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              height: 40,
              padding: "0 20px",
              borderRadius: 9999,
              background: "#FFFFFF",
              color: "#000000",
              fontSize: "0.88rem",
              fontWeight: 800,
              boxShadow: "0 0 20px rgba(255, 255, 255, 0.3)",
              transition: "transform 0.25s ease, box-shadow 0.25s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "scale(1.04)";
              e.currentTarget.style.boxShadow = "0 0 30px rgba(255, 255, 255, 0.5)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "scale(1)";
              e.currentTarget.style.boxShadow = "0 0 20px rgba(255, 255, 255, 0.3)";
            }}
          >
            Live Demo →
          </a>

          {/* Mobile Hamburger */}
          <button
            onClick={() => setMenuOpen(true)}
            aria-label="Open menu"
            className="nav-toggle"
            style={{
              display: "none",
              flexDirection: "column",
              gap: 5,
              background: "transparent",
              border: "none",
              padding: 6,
              cursor: "pointer",
            }}
          >
            <span style={{ display: "block", width: 22, height: 2, background: "#FFFFFF", borderRadius: 2 }} />
            <span style={{ display: "block", width: 22, height: 2, background: "#FFFFFF", borderRadius: 2 }} />
            <span style={{ display: "block", width: 22, height: 2, background: "#FFFFFF", borderRadius: 2 }} />
          </button>
        </div>
      </motion.header>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{
              position: "fixed",
              inset: 0,
              background: "rgba(0, 0, 0, 0.98)",
              backdropFilter: "blur(30px)",
              zIndex: 200,
              display: "flex",
              flexDirection: "column",
              padding: "40px 24px",
              overflowY: "auto",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "1.2rem", fontWeight: 800, color: "#FFFFFF" }}>TrustLens</span>
              <button
                onClick={() => setMenuOpen(false)}
                aria-label="Close menu"
                style={{
                  background: "transparent",
                  border: "none",
                  fontSize: "2.4rem",
                  color: "var(--color-text-muted)",
                  cursor: "pointer",
                  lineHeight: 1,
                }}
              >
                ×
              </button>
            </div>
            <nav style={{ marginTop: 40, display: "flex", flexDirection: "column", gap: 18 }}>
              {links.map(([href, label], i) => (
                <motion.a
                  key={href}
                  href={href}
                  onClick={() => setMenuOpen(false)}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.04 * i, duration: 0.3 }}
                  style={{
                    fontSize: "1.35rem",
                    fontWeight: 700,
                    color: "#FFFFFF",
                    padding: "8px 0",
                    borderBottom: "1px solid rgba(255,255,255,0.08)",
                  }}
                >
                  {label}
                </motion.a>
              ))}
            </nav>
          </motion.div>
        )}
      </AnimatePresence>

      <style>{`
        @media (max-width: 960px) {
          .nav-desktop { display: none !important; }
          .nav-toggle { display: flex !important; }
        }
      `}</style>
    </>
  );
}
