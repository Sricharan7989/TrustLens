import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const faqs = [
  {
    q: "Does TrustLens execute untrusted code on my host machine?",
    a: "No. All untrusted executions occur strictly inside an unprivileged Bubblewrap (bwrap) sandbox with network access disabled, fake honeytoken secrets (canaries), and an ephemeral tmpfs HOME directory. The host filesystem is never modified.",
  },
  {
    q: "What does 'BENIGN-CONSISTENT' mean?",
    a: "It means the package's observed runtime behavior is consistent with its stated purpose within the observed coverage — not that it is categorically 'safe'. TrustLens never claims mathematical safety; it claims empirical consistency within observed phases.",
  },
  {
    q: "What happens when execution coverage is thin or incomplete?",
    a: "The verdict ladder honestly abstains with INCONCLUSIVE (action: manual review). A package that fails to compile or exits prematurely never receives a false PASS. The report clearly lists which phases were and were not exercised.",
  },
  {
    q: "Is there an LLM or neural network in the verdict path?",
    a: "No. The entire classification pipeline is deterministic and rule-based. Claims extraction uses keyword capability parsing, the fingerprint correlates syscalls, and the verdict ladder evaluates weighted logic rules offline with zero hallucination risk.",
  },
  {
    q: "How does the canary honeytoken trap work?",
    a: "Every scan generates ephemeral cryptographic canary tokens planted in fake SSH keys (~/.ssh/id_rsa), cloud credentials (AWS_SECRET_ACCESS_KEY), and configs. If these tokens appear in outbound data buffers or subprocess arguments, exfiltration is mathematically proven.",
  },
  {
    q: "Does TrustLens detect time bombs and sleep-delayed execution?",
    a: "Yes. In addition to testing standard dev and CI profiles, TrustLens runs a clock-shifted (+30 days) environment variant to uncover malware that idles before triggering malicious logic.",
  },
];

export default function FAQ() {
  const [open, setOpen] = useState(null);

  return (
    <section id="faq" className="section" style={{ background: "#000000" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Frequently Asked Questions</span>
          <h2>Architecture & Verification Guarantees</h2>
          <p>
            Honest answers about sandbox boundaries, deterministic evaluation, and execution guarantees.
          </p>
        </motion.div>

        <div style={{ maxWidth: 880, margin: "0 auto", display: "flex", flexDirection: "column", gap: 12 }}>
          {faqs.map((f, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.5, delay: i * 0.05, ease: [0.16, 1, 0.3, 1] }}
              style={{
                borderRadius: "var(--radius-lg)",
                border: "1px solid rgba(255, 255, 255, 0.14)",
                background: "linear-gradient(180deg, #101014 0%, #060608 100%)",
                overflow: "hidden",
                transition: "border-color 0.25s ease",
              }}
            >
              <button
                onClick={() => setOpen(open === i ? null : i)}
                style={{
                  width: "100%",
                  padding: "24px 28px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 16,
                  background: "transparent",
                  border: "none",
                  cursor: "pointer",
                  textAlign: "left",
                }}
                aria-expanded={open === i}
              >
                <span style={{ fontSize: "1.15rem", fontWeight: 700, color: "#FFFFFF" }}>
                  {f.q}
                </span>
                <motion.span
                  animate={{ rotate: open === i ? 45 : 0 }}
                  transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                  style={{
                    fontSize: "1.8rem",
                    fontWeight: 300,
                    color: "#FFFFFF",
                    flexShrink: 0,
                    lineHeight: 1,
                  }}
                >
                  +
                </motion.span>
              </button>
              <AnimatePresence>
                {open === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    style={{ overflow: "hidden" }}
                  >
                    <div style={{ padding: "0 28px 24px 28px", color: "var(--color-text-muted)", fontSize: "1.05rem", lineHeight: 1.65 }}>
                      {f.a}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
