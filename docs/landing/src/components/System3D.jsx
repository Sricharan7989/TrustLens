import { useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Text, Line, Sphere } from "@react-three/drei";
import { motion } from "framer-motion";
import * as THREE from "three";

const NODES = [
  { pos: [-4, 1.5, 0], label: "Package", color: "#888888" },
  { pos: [-2, -1, 0], label: "Sandbox", color: "#888888" },
  { pos: [0, 1.8, 0], label: "Fingerprint", color: "#BBBBBB" },
  { pos: [2.5, 0, 0], label: "Risk", color: "#FFFFFF", accent: true },
  { pos: [4.5, 1.2, 0], label: "Report", color: "#888888" },
];
const EDGES = [[0,1],[1,2],[2,3],[3,4],[0,2],[2,4]];

function Nodes() {
  const group = useRef();
  useFrame((state) => {
    if (group.current) {
      group.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.15) * 0.15;
      group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.1) * 0.08;
    }
  });
  return (
    <group ref={group}>
      {NODES.map((n, i) => (
        <Float key={i} speed={1.5 + i * 0.3} rotationIntensity={0.2} floatIntensity={0.6}>
          <group position={n.pos}>
            <Sphere args={[n.accent ? 0.35 : 0.22, 32, 32]}>
              <meshStandardMaterial color={n.color} emissive={n.color} emissiveIntensity={n.accent ? 1.2 : 0.3} roughness={0.2} metalness={0.8} />
            </Sphere>
            {n.accent && (
              <Sphere args={[0.6, 32, 32]}>
                <meshBasicMaterial color={n.color} transparent opacity={0.15} />
              </Sphere>
            )}
            <Text position={[0, -0.5, 0]} fontSize={0.22} color={n.accent ? "#fff" : "#888888"} anchorX="center" anchorY="middle" font="https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2">
              {n.label}
            </Text>
          </group>
        </Float>
      ))}
      {EDGES.map(([a, b], i) => (
        <Line key={i} points={[NODES[a].pos, NODES[b].pos]} color={NODES[a].accent || NODES[b].accent ? "#FFFFFF" : "#333333"} lineWidth={1.5} transparent opacity={0.6} dashed={false} />
      ))}
    </group>
  );
}

export default function System3D() {
  return (
    <section id="system" className="section">
      <div className="container">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          className="section-head"
        >
          <span className="kicker">Unified analysis</span>
          <h2>From package to evidence-backed decision</h2>
          <p>Telemetry from every phase feeds into a behavioral fingerprint, compared against declared intent to produce a risk assessment and explainable report.</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
          style={{ height: 500, borderRadius: "var(--radius-lg)", border: "1px solid var(--color-border)", background: "radial-gradient(ellipse at 50% 50%, rgba(255,255,255,0.08), transparent 70%)", overflow: "hidden", position: "relative" }}
        >
          <Canvas camera={{ position: [0, 0, 8], fov: 50 }} dpr={[1, 2]}>
            <ambientLight intensity={0.5} />
            <pointLight position={[5, 5, 5]} intensity={1.5} color="#FFFFFF" />
            <pointLight position={[-5, -3, 3]} intensity={0.8} color="#AAAAAA" />
            <Nodes />
          </Canvas>
          <div style={{ position: "absolute", bottom: 20, left: 0, right: 0, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--color-text-subtle)", pointerEvents: "none" }}>
            Package → Isolated execution → Behavioral fingerprint → Risk assessment → Explainable report
          </div>
        </motion.div>
      </div>
    </section>
  );
}
