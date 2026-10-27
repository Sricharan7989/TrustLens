import { motion, useScroll } from "framer-motion";
import { useRef } from "react";

const steps = [
  {
    n: "01",
    title: "Static Intake & Claim Extraction",
    desc: "TrustLens inspects the package directory, wheels, or source distribution. It computes a cryptographic SHA-256 digest, parses setup.py, pyproject.toml, and setup.cfg, and extracts stated capabilities from the README. Claims are cataloged into an intent profile with exact line citations.",
  },
  {
    n: "02",
    title: "Isolated Sandbox Execution",
    desc: "Code executes inside an unprivileged Linux Bubblewrap (bwrap) sandbox with dropped network namespaces (CLONE_NEWNET), an ephemeral tmpfs mount, and decoy honeypot credentials. The harness tests both dev-laptop and CI profiles, plus a +30-day clock-shift variant to detect sleep-delayed payloads.",
  },
  {
    n: "03",
    title: "Kernel & Audit Hook Normalization",
    desc: "CPython sys.addaudithook() and kernel ptrace intercept every file read/write, child process execution, socket connect, and dynamic code evaluation. Events are attributed to the package root (pkg), direct dependencies (dep:requests), or Python interpreter toolchain startup.",
  },
  {
    n: "04",
    title: "Deterministic Mismatch Ladder",
    desc: "The engine computes: Observed Capabilities minus Claimed Intent. Weighted rules score discrepancies: sensitive path access, canary leakage, and hidden persistence hooks. The pipeline relies strictly on deterministic logic — zero hallucination, no black-box LLMs in the verdict path.",
  },
  {
    n: "05",
    title: "Cryptographic Verdict & Honest Abstention",
    desc: "Produces machine-readable SARIF 2.1.0, interactive HTML timelines, and JSON verdicts (MALICIOUS-EVIDENT, SUSPICIOUS, INCONCLUSIVE, or BENIGN-CONSISTENT). If coverage is incomplete due to broken imports or missing toolchains, TrustLens abstains honestly with INCONCLUSIVE.",
  },
];

export default function HowItWorks() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start end", "end start"] });

  return (
    <section id="how" className="section" ref={ref} style={{ background: "#000000" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Process Walkthrough</span>
          <h2>How TrustLens operates</h2>
          <p>
            An automated, airgapped verification workflow converting untrusted third-party dependencies into verified, evidence-backed security decisions.
          </p>
        </motion.div>

        <div style={{ position: "relative", maxWidth: 960, margin: "0 auto", paddingLeft: "20px" }}>
          {/* Vertical Track Line */}
          <div style={{ position: "absolute", left: 50, top: 20, bottom: 40, width: 2, background: "rgba(255,255,255,0.08)" }} />
          <motion.div
            style={{
              position: "absolute",
              left: 50,
              top: 20,
              width: 2,
              height: "calc(100% - 60px)",
              background: "linear-gradient(180deg, #FFFFFF, rgba(255,255,255,0.3))",
              transformOrigin: "top",
              scaleY: scrollYProgress,
              boxShadow: "0 0 12px rgba(255,255,255,0.4)",
            }}
          />

          {steps.map((s, i) => (
            <motion.div
              key={s.n}
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.7, delay: i * 0.08, ease: [0.16, 1, 0.3, 1] }}
              style={{ display: "flex", gap: 36, marginBottom: 50, position: "relative" }}
            >
              {/* Step Circle Badge */}
              <div style={{ position: "relative", flexShrink: 0 }}>
                <div style={{
                  width: 64,
                  height: 64,
                  borderRadius: "50%",
                  background: "linear-gradient(135deg, #18181C 0%, #08080A 100%)",
                  border: "2px solid rgba(255, 255, 255, 0.35)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontFamily: "var(--font-mono)",
                  fontSize: "1.2rem",
                  fontWeight: 900,
                  color: "#FFFFFF",
                  position: "relative",
                  zIndex: 2,
                  boxShadow: "0 0 20px rgba(255, 255, 255, 0.2)",
                }}>
                  {s.n}
                </div>
              </div>

              {/* Step Content */}
              <div style={{ paddingTop: 8 }}>
                <h3 style={{ fontSize: "1.5rem", fontWeight: 800, marginBottom: 10, letterSpacing: "-0.02em", color: "#FFFFFF" }}>
                  {s.title}
                </h3>
                <p style={{ color: "var(--color-text-muted)", fontSize: "1.08rem", lineHeight: 1.65, maxWidth: 700 }}>
                  {s.desc}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
