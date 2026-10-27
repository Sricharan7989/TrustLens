import { Canvas } from "@react-three/fiber";
import Scene3D from "./Scene3D.jsx";

export default function Canvas3D() {
  return (
    <Canvas camera={{ position: [0, 0, 12], fov: 60 }} dpr={[1, 2]} style={{ background: "transparent" }}>
      <Scene3D />
    </Canvas>
  );
}
