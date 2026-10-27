import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

export default function Preloader({ onComplete }) {
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let p = 0;
    const interval = setInterval(() => {
      p += Math.random() * 15 + 5;
      if (p >= 100) {
        p = 100;
        clearInterval(interval);
        setTimeout(() => { setDone(true); setTimeout(onComplete, 600); }, 400);
      }
      setProgress(Math.min(p, 100));
    }, 120);
    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <AnimatePresence>
      {!done && (
        <motion.div
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 1.05 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          style={{ position: "fixed", inset: 0, zIndex: 10000, background: "var(--color-bg)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 24 }}
        >
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            style={{ fontSize: "1.5rem", fontWeight: 800, letterSpacing: "-0.02em" }}
          >
            TrustLens
          </motion.div>
          <div style={{ width: 200, height: 2, background: "var(--color-border)", borderRadius: 1, overflow: "hidden" }}>
            <motion.div
              style={{ height: "100%", background: "var(--color-text)", borderRadius: 1, width: `${progress}%` }}
              transition={{ duration: 0.2 }}
            />
          </div>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--color-text-subtle)", letterSpacing: "0.1em" }}
          >
            {Math.round(progress)}%
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
