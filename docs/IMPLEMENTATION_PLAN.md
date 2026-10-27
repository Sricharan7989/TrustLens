# Implementation Plan — PS-1 / TrustLens Dependency Security Landing Page

## Phase 1 — Discover (complete)

- Repository: TrustLens AI — pure Python project, **no existing frontend stack** (`requirements.txt` is Python only: PyYAML, jsonschema, setuptools, wheel, packaging).
- Reference assets inspected:
  - `Header_section.png` (2168×730 PNG) — hero/header composition reference.
  - `the_other_half.mov` (2114×1496, ~19.7s @60fps) — main visual language: near-black canvas, lavender/indigo glow, sparse particles, connected-node diagram, staggered cards, purple spotlight CTA.
  - `Section_below_header.mov` — inspected; appears to be an editor/OpenCode coding session (terminal, test results, composer), **not a website section**. Interpreted honestly per master prompt §2.C / §7.
- No frontend dependencies installed; no `webui/` folder exists.
- Tech stack decision (v1, superseded): single self-contained HTML file with embedded CSS + vanilla JS.
- Tech stack decision (v2, current): **React + Vite + Three.js (React Three Fiber + drei) + Framer Motion**, located in `docs/landing/`. Design tokens in `src/index.css`; components in `src/components/`. Initial bundle 370 KB (gzipped 117 KB); 3D scene (916 KB gzipped 243 KB) is lazy-loaded after first paint. No new top-level folder (lives under existing `docs/`). No Python files touched.

## Phase 2 — Plan & document (complete)

- `docs/IMPLEMENTATION_PLAN.md` — complete (this file).
- `docs/REFERENCE_ANALYSIS.md` — asset-by-asset interpretation (complete).
- `docs/DESIGN_SYSTEM.md` — color, type, spacing, radius, border, glow, icon rules (complete).
- `docs/ANIMATIONS.md` — per-animation inventory with IDs, triggers, durations, easing, reduced-motion fallbacks (complete).
- `docs/QA_CHECKLIST.md` — responsive/a11y/functional/animation checks (created; manual browser checks pending).

## Phase 3 — Build layout & core visuals (complete)

- Navigation, hero (eyebrow/headline/supporting/CTAs/tabbed package-analysis panel), trust strip, problem banner, connected-node diagram, capability cards, how-it-works steps, report preview, final CTA spotlight, footer.
- Copy: PS-1 / TrustLens messaging, no unsupported security claims, sample data labeled illustrative.
- Real repo commands referenced where accurate (`make demo`, `python -m trustlens scan`).

## Phase 4 — Interaction & motion (complete)

- Shared CSS motion tokens; section reveals; card hovers; diagram node/line reveal; report transitions; CTA spotlight drift; reduced-motion handling via `prefers-reduced-motion`.

## Phase 5 — Refine (complete)

- Fluid `clamp()` typography; single 768px breakpoint; tested widths targeted: 360/390/768/1024/1440/1920.

## Phase 6 — Validate (pending manual browser checks)

- [ ] Open page in browser; inspect console for errors.
- [ ] Keyboard navigation, mobile menu, tabs/buttons, sample labeling, reduced-motion mode.
- [ ] No horizontal overflow, broken links, dead buttons at tested widths.

## Phase 7 — Report (complete — this document)

---

### Constraints honored
- No "100% detection" / "safe" / "zero false positives" claims.
- No fabricated customer logos, integrations, benchmarks, or external URLs.
- Simulated/sample results clearly labeled "Illustrative sample — demo data."
- Backend CLI is real where referenced; no fake runnable install command for a non-existent backend.
- Page lives under existing `docs/` folder (no new top-level folder).
- AGENTS.md ownership respected: no files outside `docs/` were created or modified; no Python code touched.

### Deliverables
- `docs/landing/` — Vite + React + Three.js landing page (entry `index.html`, source in `src/`)
- `docs/REFERENCE_ANALYSIS.md`
- `docs/DESIGN_SYSTEM.md`
- `docs/ANIMATIONS.md`
- `docs/QA_CHECKLIST.md`
- `docs/IMPLEMENTATION_PLAN.md` (this file)

### How to launch
```
cd docs/landing
npm install
npm run dev        # dev server (http://localhost:5173)
npm run build      # production build -> dist/
```
No Python dependencies required; node/npm only.

### How to launch
Open `docs/landing/index.html` directly in any browser. No build step, no server, no dependencies required.
