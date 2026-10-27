import { motion } from "framer-motion";
import { IconTerminal, IconFiles, IconNetwork, IconCpu, IconKey, IconScale } from "./Icons.jsx";

const chips = [
  {
    icon: <IconTerminal size={24} color="#FFFFFF" />,
    title: "Full Lifecycle Execution Interception",
    desc: "Hooks into pip setup.py egg_info, wheel builds, interpreter startup hooks (.pth and sitecustomize.py), runtime import-all trigger matrix, and CLI entry points.",
    metric: "5 Stages Observed",
  },
  {
    icon: <IconFiles size={24} color="#FFFFFF" />,
    title: "Filesystem & Secret Path Traps",
    desc: "Intercepts filesystem mutations outside the isolated package root. Decoys planted across ~/.ssh/id_rsa, ~/.aws/credentials, ~/.docker/config.json, and /etc/passwd.",
    metric: "Normalized Paths",
  },
  {
    icon: <IconNetwork size={24} color="#FFFFFF" />,
    title: "Airgapped Network Egress Sinkhole",
    desc: "Disables host network access with Linux network namespaces. Intercepts raw socket() and connect() syscalls — logging destination IP, port, and staged buffer payloads.",
    metric: "0 B Outbound Leaked",
  },
  {
    icon: <IconCpu size={24} color="#FFFFFF" />,
    title: "Subprocess Spawning & Ptrace Syscalls",
    desc: "Traces process tree creation via CPython audit hooks and kernel ptrace. Inspects child process argv vectors, shell executions (/bin/sh, curl), and decoded base64 exec.",
    metric: "Lineage Tracing",
  },
  {
    icon: <IconKey size={24} color="#FFFFFF" />,
    title: "Canary-in-Bytes Exfiltration Traps",
    desc: "Generates high-entropy, per-run honeytoken tokens planted in fake environment variables and secret files. Token matching in outgoing buffers proves data theft mathematically.",
    metric: "Cryptographic Proof",
  },
  {
    icon: <IconScale size={24} color="#FFFFFF" />,
    title: "README Claims vs. Runtime Reality",
    desc: "Extracts explicitly advertised intents from pyproject.toml classifiers, entry points, and README documentation. Subtracts claimed intent from observed reality.",
    metric: "Deterministic Rules",
  },
];

export default function TrustStrip() {
  return (
    <section id="trust" className="section" style={{ background: "#050507", borderTop: "1px solid rgba(255,255,255,0.08)", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Telemetry Signals</span>
          <h2>Every critical signal, one unified fingerprint</h2>
          <p>
            TrustLens correlates syscalls, file audits, environment reads, and network egress across five execution phases, normalizing raw telemetry into an immutable behavioral fingerprint.
          </p>
        </motion.div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 20 }}>
          {chips.map((c, i) => (
            <motion.div
              key={c.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.6, delay: i * 0.06, ease: [0.16, 1, 0.3, 1] }}
              style={{
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                padding: "30px 28px",
                borderRadius: "var(--radius-lg)",
                border: "1px solid rgba(255, 255, 255, 0.12)",
                background: "linear-gradient(180deg, #0F0F12 0%, #060608 100%)",
                boxShadow: "0 10px 30px -10px rgba(0,0,0,0.8)",
                transition: "all 0.3s ease",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.4)";
                e.currentTarget.style.transform = "translateY(-4px)";
                e.currentTarget.style.boxShadow = "0 20px 40px -10px rgba(255, 255, 255, 0.1)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.12)";
                e.currentTarget.style.transform = "translateY(0)";
                e.currentTarget.style.boxShadow = "0 10px 30px -10px rgba(0,0,0,0.8)";
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                  <div style={{
                    width: 44,
                    height: 44,
                    borderRadius: 10,
                    display: "grid",
                    placeItems: "center",
                    background: "rgba(255, 255, 255, 0.08)",
                    border: "1px solid rgba(255, 255, 255, 0.18)",
                    color: "#FFFFFF",
                  }}>
                    {c.icon}
                  </div>
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.78rem",
                    fontWeight: 700,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    color: "var(--color-chrome)",
                    background: "rgba(255, 255, 255, 0.05)",
                    padding: "3px 10px",
                    borderRadius: 4,
                    border: "1px solid rgba(255, 255, 255, 0.1)",
                  }}>
                    {c.metric}
                  </span>
                </div>

                <h3 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#FFFFFF", marginBottom: 10 }}>
                  {c.title}
                </h3>
                <p style={{ color: "var(--color-text-muted)", fontSize: "0.96rem", lineHeight: 1.65 }}>
                  {c.desc}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
