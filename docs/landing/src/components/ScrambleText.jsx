import { useState, useEffect, useRef } from "react";

const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&";

export default function ScrambleText({ text, className = "", delay = 0 }) {
  const [display, setDisplay] = useState("");
  const ref = useRef(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true;
        let frame = 0;
        const totalFrames = text.length * 3;
        const interval = setInterval(() => {
          frame++;
          let result = "";
          for (let i = 0; i < text.length; i++) {
            if (text[i] === " ") { result += " "; continue; }
            const progress = frame / totalFrames;
            const charProgress = (i / text.length);
            if (progress > charProgress + 0.3) {
              result += text[i];
            } else {
              result += CHARS[Math.floor(Math.random() * CHARS.length)];
            }
          }
          setDisplay(result);
          if (frame >= totalFrames) {
            setDisplay(text);
            clearInterval(interval);
          }
        }, 30);
        setTimeout(() => {}, delay * 1000);
      }
    }, { threshold: 0.5 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [text, delay]);

  return <span ref={ref} className={className}>{display || text}</span>;
}
