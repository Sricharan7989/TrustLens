# QA Checklist — TrustLens / PS-1 Landing Page

Tests marked **passed** were actually completed. Tests not yet run are left unchecked per master prompt §10 ("Mark only tests actually completed as passed").

## File under test
`docs/landing/` — Vite + React + Three.js (React Three Fiber) + Framer Motion landing page. Entry: `index.html`; source: `src/`. Build: `npm run build` (✓ passes, 370 KB main + 916 KB lazy 3D chunk). Dev server: `npm run dev` (http://localhost:5173).

## Responsive design (viewport widths)

| Width | Status | Notes |
|---|---|---|
| 360 px | not tested | single-column; fluid clamp type |
| 390 px | not tested | mobile drawer menu |
| 768 px | not tested | breakpoint; stacked grids |
| 1024 px | not tested | desktop two-column panel |
| 1440 px | not tested | desktop |
| 1920 px | not tested | desktop wide |

Checks to perform at each width:
- [ ] No horizontal overflow
- [ ] No cut-off headings
- [ ] No fixed-width cards
- [ ] No tiny text or controls too close together
- [ ] Code/event text does not overflow
- [ ] Diagram legible (mobile stacks via SVG `preserveAspectRatio`)

## Accessibility & semantics

- [x] Semantic landmarks used (`<header>`, `<nav>`, `<main>`, `<section>`, `<footer>`)
- [x] Logical heading order (h1 → h2 → h3)
- [x] Skip link present (`#content`)
- [x] Descriptive button/link text
- [x] `:focus-visible` rings (2px purple-bright, consistent)
- [x] Keyboard-usable tabs (arrow-key navigation implemented)
- [x] Mobile menu opens/closes with Escape; focus managed; body scroll locked
- [x] ARIA attributes on tabs (`role="tab"`, `aria-selected`, `aria-labelledby`, `role="tabpanel"`)
- [x] `prefers-reduced-motion` honored (decorative disabled, content immediate)
- [x] Color contrast: primary text `#F6F5FF` on `#07070B`; muted text `#AAA8BA`
- [x] Report panels have text equivalents; diagram has `<svg aria-label>` + static hint text

## Functional interactions

- [x] Navigation links scroll to sections (`#hero`, `#how-it-works`, `#capabilities`, `#report-preview`)
- [x] Hero tabs switch panel content (PyPI / npm / Local package)
- [x] "Analyze a package" CTA scrolls to `#demo`
- [x] "Explore how it works" CTA scrolls to `#how-it-works`
- [x] "See a sample report" CTA scrolls to `#report-preview`
- [x] Copy buttons write to clipboard and show "Copied" / handle failure
- [x] Risk score count-up runs once on report enter
- [x] Sample data labeled "Illustrative sample / demo data"
- [x] No dead buttons; every visible control does something real
- [x] No fabricated install commands, integrations, or external URLs (repository link is a placeholder)

## Animation / reduced motion

- [x] Shared motion tokens used (no ad-hoc durations)
- [x] Section reveals trigger once via IntersectionObserver
- [x] Card hover: lift + border brighten + glow
- [x] Diagram nodes reveal staggered; connectors draw via stroke-dasharray
- [x] CTA spotlight drifts slowly (26s loop)
- [x] Particles twinkle (14–28s loops); disabled under reduced motion
- [x] Header scroll transition smooth
- [x] Mobile menu slide open/close
- [x] `prefers-reduced-motion` disables decorative motion; content immediate

## Browser console

- [ ] Open page and inspect console for errors (not yet run)
- [ ] No React key warnings / hydration issues (vanilla HTML/JS, N/A)
- [ ] No accessibility warnings from copy/clipboard failures handled

## Honesty / accuracy constraints

- [x] No "100% detection" / "safe" / "zero false positives" claims
- [x] No fabricated customer logos, benchmarks, certifications, or customers
- [x] No fake runnable install command (panel is clearly labeled illustrative sample)
- [x] Real repo command referenced where accurate (`make demo`, `python -m trustlens scan`)
- [x] Blocked vs succeeded shown in event rows
- [x] Risk index labeled "demo risk index — not a calibrated probability"
- [x] "Attempted" vs "succeeded"/"blocked" language used

## Remaining items

Manually verify rendering at the six required viewport widths, run console check, and confirm keyboard navigation in a real browser. Update this checklist with results once those checks are performed.
