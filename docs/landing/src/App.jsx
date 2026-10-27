import { useEffect, useState } from "react";
import Lenis from "lenis";

import Nav from "./components/Nav.jsx";
import Hero from "./components/Hero.jsx";
import TrustStrip from "./components/TrustStrip.jsx";
import Marquee from "./components/Marquee.jsx";
import Problem from "./components/Problem.jsx";
import Diagram from "./components/Diagram.jsx";
import BentoGrid from "./components/BentoGrid.jsx";
import HowItWorks from "./components/HowItWorks.jsx";
import ReportPreview from "./components/ReportPreview.jsx";
import Comparison from "./components/Comparison.jsx";
import Metrics from "./components/Metrics.jsx";
import FAQ from "./components/FAQ.jsx";
import FinalCTA from "./components/FinalCTA.jsx";
import Footer from "./components/Footer.jsx";
import BackToTop from "./components/BackToTop.jsx";

export default function App() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const lenis = new Lenis({
      duration: 1.1,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      wheelMultiplier: 1,
      touchMultiplier: 2,
    });

    function raf(time) {
      lenis.raf(time);
      requestAnimationFrame(raf);
    }
    requestAnimationFrame(raf);

    lenis.on("scroll", ({ progress: p }) => setProgress(p));

    // Smooth anchor navigation with Lenis
    const handleAnchor = (e) => {
      const anchor = e.target.closest('a[href^="#"]');
      if (anchor) {
        const targetId = anchor.getAttribute("href");
        if (targetId && targetId !== "#") {
          const targetEl = document.querySelector(targetId);
          if (targetEl) {
            e.preventDefault();
            lenis.scrollTo(targetEl, { offset: -70, duration: 1.2 });
          }
        }
      }
    };
    document.addEventListener("click", handleAnchor);

    // Follower cursor that only shows when mouse moves
    const dot = document.querySelector(".cursor-dot");
    const ring = document.querySelector(".cursor-ring");
    let mx = -100, my = -100, rx = -100, ry = -100;
    let hasMoved = false;

    const onMove = (e) => {
      mx = e.clientX;
      my = e.clientY;
      if (!hasMoved) {
        hasMoved = true;
        document.body.classList.add("cursor-active");
      }
    };
    window.addEventListener("mousemove", onMove);

    let animId;
    function cursorLoop() {
      rx += (mx - rx) * 0.2;
      ry += (my - ry) * 0.2;
      if (dot) {
        dot.style.left = `${mx}px`;
        dot.style.top = `${my}px`;
      }
      if (ring) {
        ring.style.left = `${rx}px`;
        ring.style.top = `${ry}px`;
      }
      animId = requestAnimationFrame(cursorLoop);
    }
    cursorLoop();

    const onOver = (e) => {
      if (e.target.closest("a, button, [data-magnetic]")) {
        document.body.classList.add("cursor-hover");
      }
    };
    const onOut = () => document.body.classList.remove("cursor-hover");
    document.addEventListener("mouseover", onOver);
    document.addEventListener("mouseout", onOut);

    return () => {
      lenis.destroy();
      cancelAnimationFrame(animId);
      document.removeEventListener("click", handleAnchor);
      window.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseover", onOver);
      document.removeEventListener("mouseout", onOut);
    };
  }, []);

  return (
    <>
      <div className="scroll-progress" style={{ width: `${progress * 100}%` }} />
      <div className="cursor-dot" />
      <div className="cursor-ring" />
      <Nav />
      <main id="content">
        <Hero />
        <TrustStrip />
        <Marquee />
        <Problem />
        <Diagram />
        <BentoGrid />
        <HowItWorks />
        <ReportPreview />
        <Comparison />
        <Metrics />
        <FAQ />
        <FinalCTA />
      </main>
      <Footer />
      <BackToTop />
    </>
  );
}
