import { motion } from "framer-motion";
import { IconTerminal, IconNetwork, IconFiles, IconCpu, IconScale, IconShield, IconKey, IconClock } from "./Icons.jsx";

const items = [
  {
    icon: <IconTerminal size={28} color="#FFFFFF" />,
    title: "Install-Time & Startup Hook Interception",
    tag: "BOOTSTRAP AUDIT",
    attack: "Malicious packages execute code during pip install via setup.py egg_info, setup.cfg cmdclass overrides, or drop stealthy .pth runtime files that hijack every future Python process.",
    defense: "TrustLens snapshots site-packages before and after installation, diffing newly created startup hooks (.pth, sitecustomize.py, usercustomize.py). Runs in an isolated Linux Bubblewrap sandbox with an ephemeral overlayfs.",
    evidence: "Generates an immutable diff of mutated interpreter hooks, recording filesystem paths, sequence timestamps, and line-level code lineage.",
    size: "large",
    phases: ["setup.py install", ".pth persistence", "sitecustomize", "module import", "cli call"],
  },
  {
    icon: <IconNetwork size={28} color="#FFFFFF" />,
    title: "Network Egress & DNS Exfiltration Sinkhole",
    tag: "ZERO-EGRESS AIRGAP",
    attack: "Infostealers stage stolen credentials and attempt HTTPS beaconing to attacker C2 servers, Telegram webhooks, or Discord webhooks during dependency resolution.",
    defense: "The sandbox strictly unshares the network namespace (CLONE_NEWNET), dropping all outbound network interfaces. A loopback sinkhole intercepts every connect(), sendto(), and DNS query.",
    evidence: "The egress attempt itself constitutes cryptographic proof of malicious intent. Destination IPs, ports, and raw byte buffers are logged offline without allowing data leakage.",
    size: "medium",
    accent: true,
  },
  {
    icon: <IconFiles size={28} color="#FFFFFF" />,
    title: "Sensitive Path & Honeytoken Canary Traps",
    tag: "SECRET ISOLATION",
    attack: "Targeted supply-chain payloads crawl the host filesystem searching for ~/.ssh/id_rsa, ~/.aws/credentials, ~/.docker/config.json, ~/.npmrc, and /etc/passwd.",
    defense: "The sandbox injects a synthetic HOME directory populated with mathematically unique, per-scan canary tokens embedded in decoy credential paths and environment variables.",
    evidence: "Any file read targeting sensitive credential locations trips an immediate alarm. If canary bytes appear in network buffers or subprocess arguments, exfiltration is mathematically verified.",
    size: "medium",
  },
  {
    icon: <IconCpu size={28} color="#FFFFFF" />,
    title: "Subprocess Spawning & Dynamic Code Exec",
    tag: "PROCESS TREE TRACING",
    attack: "Payloads spawn /bin/sh, curl, or base64-decoded eval() snippets to bypass static AST parsers and execute memory-only shellcode.",
    defense: "CPython sys.addaudithook() intercepts os.system, subprocess.Popen, and compile(). Low-level ptrace / strace tracks raw clone() and execve() syscall boundaries.",
    evidence: "Captures full argv parameter arrays, decoded execution strings, parent-child PID lineage, and flags unauthorized shells.",
    size: "small",
  },
  {
    icon: <IconScale size={28} color="#FFFFFF" />,
    title: "Declared Intent vs. Runtime Reality",
    tag: "MISMATCH VERIFICATION",
    attack: "Attackers disguise malware as benign utility libraries (e.g. string formatting, ASCII art, color logging) with convincing README descriptions.",
    defense: "TrustLens statically parses pyproject.toml and README documentation to extract explicitly licensed capabilities. The mismatch engine calculates: Observed Behavior minus Declared Intent.",
    evidence: "Produces verifiable findings citing the exact README line and contrasting it against the violating runtime syscall sequence number.",
    size: "small",
  },
  {
    icon: <IconShield size={28} color="#FFFFFF" />,
    title: "Deterministic Rule Ladder & Honest Coverage",
    tag: "NO FALSE PASSES",
    attack: "Complex packages with missing native dependencies or anti-sandbox checks fail to run, causing traditional heuristic scanners to report a false 'Clean' pass.",
    defense: "Pure deterministic logic: MALICIOUS-EVIDENT, SUSPICIOUS, INCONCLUSIVE, or BENIGN-CONSISTENT. If execution coverage is incomplete, TrustLens abstains honestly with INCONCLUSIVE.",
    evidence: "Includes a granular coverage manifest detailing callables tested, exit codes, and explicit limitations. Zero hallucination risk — no black-box LLMs in the verdict path.",
    size: "small",
  },
];

export default function BentoGrid() {
  return (
    <section id="capabilities" className="section" style={{ background: "#000000" }}>
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Deep Telemetry Architecture</span>
          <h2>What the analysis engine observes</h2>
          <p>
            An in-depth, multi-layered telemetry matrix capturing every syscall, persistence hook, and credential read across five isolated execution phases.
          </p>
        </motion.div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gridAutoRows: "minmax(220px, auto)",
          gap: 20,
        }}>
          {items.map((it, i) => {
            const span = it.size === "large" ? "span 2" : it.size === "medium" ? "span 2" : "span 1";
            const rowSpan = it.size === "large" ? "span 2" : "span 1";
            return (
              <motion.div
                key={it.title}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.1 }}
                transition={{ duration: 0.6, delay: i * 0.06, ease: [0.16, 1, 0.3, 1] }}
                whileHover={{ y: -6 }}
                style={{
                  gridColumn: span,
                  gridRow: rowSpan,
                  padding: "36px 32px",
                  borderRadius: "var(--radius-xl)",
                  border: "1px solid rgba(255, 255, 255, 0.14)",
                  background: "linear-gradient(180deg, #0F0F12 0%, #060608 100%)",
                  boxShadow: "0 16px 40px -10px rgba(0,0,0,0.85)",
                  position: "relative",
                  overflow: "hidden",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  transition: "all 0.3s ease",
                }}
                onMouseMove={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect();
                  const x = e.clientX - rect.left;
                  const y = e.clientY - rect.top;
                  e.currentTarget.style.background = `radial-gradient(circle at ${x}px ${y}px, rgba(255, 255, 255, 0.12), transparent 60%), linear-gradient(180deg, #141418 0%, #060608 100%)`;
                  e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.45)";
                  e.currentTarget.style.boxShadow = "0 20px 50px -10px rgba(255, 255, 255, 0.12)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "linear-gradient(180deg, #0F0F12 0%, #060608 100%)";
                  e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.14)";
                  e.currentTarget.style.boxShadow = "0 16px 40px -10px rgba(0,0,0,0.85)";
                }}
              >
                <div>
                  {/* Top Bar with Icon & Tag */}
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
                    <div style={{
                      width: 48,
                      height: 48,
                      borderRadius: 12,
                      background: "rgba(255, 255, 255, 0.08)",
                      border: "1px solid rgba(255, 255, 255, 0.2)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      boxShadow: "0 0 20px rgba(255, 255, 255, 0.08)",
                    }}>
                      {it.icon}
                    </div>
                    <span style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.75rem",
                      fontWeight: 800,
                      letterSpacing: "0.1em",
                      textTransform: "uppercase",
                      padding: "4px 12px",
                      borderRadius: 6,
                      background: "rgba(255, 255, 255, 0.06)",
                      color: "#FFFFFF",
                      border: "1px solid rgba(255, 255, 255, 0.16)",
                    }}>
                      {it.tag}
                    </span>
                  </div>

                  {/* Title */}
                  <h3 style={{
                    fontSize: it.size === "large" ? "1.65rem" : "1.3rem",
                    fontWeight: 800,
                    marginBottom: 16,
                    letterSpacing: "-0.03em",
                    color: "#FFFFFF",
                  }}>
                    {it.title}
                  </h3>

                  {/* Structured Deep-Dive Content */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 14 }}>
                    <div>
                      <span style={{ fontSize: "0.75rem", fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-chrome)", display: "block", marginBottom: 4 }}>
                        Attack Vector
                      </span>
                      <p style={{ color: "var(--color-text-muted)", fontSize: "0.95rem", lineHeight: 1.6 }}>
                        {it.attack}
                      </p>
                    </div>

                    <div>
                      <span style={{ fontSize: "0.75rem", fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: "#FFFFFF", display: "block", marginBottom: 4 }}>
                        Interception & Defense
                      </span>
                      <p style={{ color: "var(--color-silver)", fontSize: "0.95rem", lineHeight: 1.6 }}>
                        {it.defense}
                      </p>
                    </div>

                    {it.size !== "small" && (
                      <div>
                        <span style={{ fontSize: "0.75rem", fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-chrome)", display: "block", marginBottom: 4 }}>
                          Logged Evidence Chain
                        </span>
                        <p style={{ color: "var(--color-text-subtle)", fontSize: "0.9rem", lineHeight: 1.6 }}>
                          {it.evidence}
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Large Card Phase Badges */}
                {it.size === "large" && (
                  <div style={{ marginTop: 24, paddingTop: 18, borderTop: "1px solid rgba(255,255,255,0.08)", display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {it.phases.map((p) => (
                      <span
                        key={p}
                        style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.82rem",
                          fontWeight: 600,
                          padding: "5px 12px",
                          borderRadius: 6,
                          background: "rgba(255, 255, 255, 0.06)",
                          color: "#FFFFFF",
                          border: "1px solid rgba(255, 255, 255, 0.14)",
                        }}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                )}
              </motion.div>
            );
          })}
        </div>
      </div>
      <style>{`
        @media (max-width: 1040px) {
          #capabilities .container > div:last-child {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
        @media (max-width: 680px) {
          #capabilities .container > div:last-child {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  );
}
