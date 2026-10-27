import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";

function Counter({ to, suffix = "", label, sub }) {
  const [val, setVal] = useState(0);
  const ref = useRef(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting && !started.current) {
        started.current = true;
        const start = performance.now();
        const dur = 1400;
        const tick = (now) => {
          const p = Math.min((now - start) / dur, 1);
          const eased = 1 - Math.pow(1 - p, 3);
          setVal(Math.round(eased * to));
          if (p < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
      }
    }, { threshold: 0.15 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [to]);

  return (
    <div ref={ref} style={{ textAlign: "center", padding: "16px" }}>
      <div style={{
        fontSize: "clamp(3.6rem, 6.5vw, 5.5rem)",
        fontWeight: 900,
        lineHeight: 1,
        letterSpacing: "-0.04em",
        background: "linear-gradient(180deg, #FFFFFF 0%, #A0A0A8 100%)",
        WebkitBackgroundClip: "text",
        backgroundClip: "text",
        color: "transparent",
        textShadow: "0 0 30px rgba(255, 255, 255, 0.2)",
      }}>
        {val}{suffix}
      </div>
      <div style={{ marginTop: 12, fontSize: "1.2rem", color: "#FFFFFF", fontWeight: 800 }}>
        {label}
      </div>
      {sub && (
        <div style={{ marginTop: 6, fontSize: "0.92rem", color: "var(--color-chrome)", fontFamily: "var(--font-mono)" }}>
          {sub}
        </div>
      )}
    </div>
  );
}

export default function Metrics() {
  return (
    <section className="section" style={{
      borderTop: "1px solid rgba(255, 255, 255, 0.08)",
      borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
      background: "#050507",
    }}>
      <div className="container">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 24 }}>
          <Counter to={5} label="Execution Phases" sub="install · startup · import · call · cli" />
          <Counter to={2} label="Runtime Profiles" sub="dev-laptop vs CI environment" />
          <Counter to={12} label="Observed Capabilities" sub="network, files, tokens, processes" />
          <Counter to={10} label="Deterministic Rules" sub="weighted ladder with zero LLM" />
        </div>
      </div>
    </section>
  );
}
