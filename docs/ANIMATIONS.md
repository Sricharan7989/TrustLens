# Animation System — TrustLens / PS-1 Landing Page

Source: `docs/landing/index.html` (embedded CSS `<style>` + `<script>`). Every implemented animation/transition is inventoried below with a unique ID, per master prompt §6.3 / §10 (ANIMATIONS.md).

## Motion tokens (shared)

| Token | Value | Use |
|---|---|---|
| `--motion-fast` | `160ms` | Small hover/focus response |
| `--motion-ui` | `220ms` | Tabs, buttons, toggles, nav states |
| `--motion-card` | `280ms` | Card hover and small depth changes |
| `--motion-reveal` | `620ms` | Section entrances |
| `--motion-feature` | `760ms` | Larger hero/diagram entrances |
| `--ease-standard` | `cubic-bezier(0.22, 1, 0.36, 1)` | Soft, confident entrance |
| `--ease-emphasized` | `cubic-bezier(0.16, 1, 0.3, 1)` | Hero / feature reveal |
| `--ease-exit` | `cubic-bezier(0.4, 0, 1, 1)` | Exit / fade away |

Stagger: consistent small stagger `50–100ms` (used as `70ms` / `140ms` / `210ms` transition delays). All motion uses compositor-friendly `transform` and `opacity` only; no layout-property animation, no continuous blur filters, no animated shadows, no repeated state updates per frame.

## Interaction-state table

| State | Target | Visual change | Token |
|---|---|---|---|
| hover | `.nav-links a` | color → text; underline scaleX 0→1 | `--motion-fast` |
| hover/focus | `.nav-cta` | brighter purple, glow, −1px lift | `--motion-fast` |
| focus-visible | buttons, links, tabs | 2px purple-bright outline, offset | n/a (instant ring) |
| hover | `.chip-card` | border brighten, −3px lift, shadow | `--motion-card` |
| hover | `.card` | border brighten, −4px lift, elevated shadow | `--motion-card` |
| hover | `.card.accent` | glow shadow | `--motion-card` |
| hover | `.btn-primary` | brighter purple, glow, −1px lift | `--motion-fast` |
| hover | `.btn-outline` | border brighten, text purple, active surface | `--motion-fast` |
| active tab | `.tab` | bottom underline 2px purple-bright | `--motion-fast` |
| active report tab | `.report-tab` | bottom underline | `--motion-fast` |
| hover | `.ev-copy` | border/text purple, tinted bg | `--motion-fast` |
| scroll | header | translucent bg + stronger border | `--motion-ui` |
| open/close | mobile menu | opacity + transform (slide) | `--motion-ui` |
| tab change | `.tabpanels` | coordinated fade/translate | `--motion-ui` |
| score count-up | `#risk-score` | 0 → 72 over 700ms ease-out | 700ms custom |

## Animation inventory

### A-1 Ambient drift (layered glow fields)
- **Component/selector:** `.ambient::before`, `.ambient::after`
- **Purpose:** Deep violet/indigo atmospheric glow behind the black canvas; bridges sections.
- **Trigger:** page load (continuous)
- **Initial/final:** `translate(0,0)` ↔ `translate(14px,-14px)`
- **Properties animated:** `transform`
- **Duration/delay/easing:** 24s / 28s, `ease-in-out`, `infinite alternate`; second layer 6s delay
- **Repeats:** yes, indefinite
- **Desktop/tablet/mobile:** all viewports (fixed background)
- **Reduced-motion fallback:** animation removed; static gradients remain
- **Performance:** compositor-only transform; fixed position; no scroll lag
- **Source file:** `docs/landing/index.html` (CSS `.ambient::before/after`, `@keyframes drift`)

### A-2 Particle twinkle (sparse stars)
- **Component/selector:** `.particle` (28 injected divs via JS)
- **Purpose:** Sparse tiny star-like particles that softly twinkle; restrained ambient speckle.
- **Trigger:** page load (continuous); skipped under `prefers-reduced-motion`
- **Initial/final:** `opacity 0` ↔ `0.5`; `scale(1)` ↔ `1.2`; slight translate
- **Properties animated:** `opacity`, `transform`
- **Duration/delay/easing:** 14–28s per loop, `ease-in-out`, `infinite`; random delay 0–20s
- **Repeats:** yes, infinite
- **Desktop/tablet/mobile:** all; count fixed at 28; reduced to static under reduced motion
- **Reduced-motion fallback:** `animation: none`; `opacity: 0.15` static; transform removed
- **Performance:** small fixed count; compositor-only; injected once at load
- **Source file:** `docs/landing/index.html` (CSS `@keyframes twinkle`; JS particle injection)

### A-3 CTA spotlight drift
- **Component/selector:** `.spotlight`
- **Purpose:** Broad soft violet spotlight/beam behind the final CTA; slow gradient drift.
- **Trigger:** page load (continuous)
- **Initial/final:** `scale(1)` ↔ `scale(1.12) translate(12px,-8px)`
- **Properties animated:** `transform`
- **Duration/delay/easing:** 26s, `ease-in-out`, `infinite alternate`
- **Repeats:** yes, infinite
- **Desktop/tablet/mobile:** all (fixed-position pseudo-light)
- **Reduced-motion fallback:** animation removed; static opacity 0.35, scale 1
- **Performance:** single pseudo-element, blur filter static (not animated), transform only
- **Source file:** `docs/landing/index.html` (CSS `.spotlight`, `@keyframes spotlightDrift`)

### A-4 Hero entrance sequence
- **Component/selector:** `.hero` (reveal), `.hero-eyebrow`, `h1`, `.hero-sub`, `.hero-actions`, `.hero-panel` (stagger-1)
- **Purpose:** Intentional sequenced fade/vertical reveal of eyebrow → headline → supporting copy → CTAs → analysis panel. Readable immediately; no long wait.
- **Trigger:** scroll into view (IntersectionObserver, threshold 0.12)
- **Initial/final:** `opacity 0` → `1`; `translateY(18px) scale(0.985)` → `translateY(0) scale(1)`
- **Properties animated:** `opacity`, `transform`
- **Duration/delay/easing:** 620ms, `cubic-bezier(0.22,1,0.36,1)`; stagger delays 0 / 70ms / 140ms / 210ms
- **Repeats:** once (reveal class removed from observation after first visible)
- **Desktop/tablet/mobile:** all; mobile headline scales via clamp
- **Reduced-motion fallback:** content immediate in final state; no animation
- **Performance:** transform+opacity only; observed once then unobserved
- **Source file:** `docs/landing/index.html` (CSS `.reveal`; JS IntersectionObserver)

### A-5 Navigation hover / active state
- **Component/selector:** `.nav-links a` (underline pseudo-element)
- **Purpose:** Fast color/opacity change + subtle underline glow on hover/active.
- **Trigger:** hover / focus / active section
- **Initial/final:** underline `scaleX(0)` → `1`; color muted → text
- **Properties animated:** `transform` (scaleX), `color`
- **Duration/delay/easing:** 160–220ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** no (state-based)
- **Desktop/tablet/mobile:** desktop only (mobile menu replaces links)
- **Reduced-motion fallback:** transitions immediate/shorter via reduced-motion media (transitions still apply but are fast); color change preserved
- **Performance:** compositor-only transform
- **Source file:** `docs/landing/index.html` (CSS `.nav-links a::after`)

### A-6 Header scroll state
- **Component/selector:** `.header` (`.scrolled` class via JS)
- **Purpose:** Sticky nav gains slightly stronger translucent background and border on scroll.
- **Trigger:** scroll (requestAnimationFrame-throttled)
- **Initial/final:** `rgba(7,7,11,0.85)` → `0.95`; border quiet → hover
- **Properties animated:** `background-color`, `border-color`
- **Duration/delay/easing:** 220ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** no (state-based)
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** transition still applies (short); not decorative
- **Performance:** rAF-throttled; color properties only
- **Source file:** `docs/landing/index.html` (JS scroll handler; CSS `.header.scrolled`)

### A-7 Mobile menu open/close
- **Component/selector:** `.mobile-menu`
- **Purpose:** Drawer animates opacity + transform; manages focus; closes on Escape; restores focus.
- **Trigger:** click toggle / close / Escape key
- **Initial/final:** `translateX(100%)` → `0` (open); reverse (close)
- **Properties animated:** `transform`
- **Duration/delay/easing:** 220ms, `cubic-bezier(0.16,1,0.3,1)`
- **Repeats:** no (state-based)
- **Desktop/tablet/mobile:** mobile only (≤768px)
- **Reduced-motion fallback:** still animates (essential interaction, not decorative)
- **Performance:** transform only; body scroll locked on open
- **Source file:** `docs/landing/index.html` (JS open/close; CSS `.mobile-menu.open`)

### A-8 Scroll-triggered section reveals
- **Component/selector:** all `.reveal` elements (headings, panels, cards, diagram, steps, report, CTA)
- **Purpose:** Sections, headings, body text and visual panels reveal on first entry into view.
- **Trigger:** scroll into view (IntersectionObserver)
- **Initial/final:** `opacity 0` → `1`; `translateY(18px) scale(0.985)` → `0 scale(1)`
- **Properties animated:** `opacity`, `transform`
- **Duration/delay/easing:** 620ms (sections) / 760ms (feature), `cubic-bezier(0.22,1,0.36,1)`; stagger groups 70/140/210ms
- **Repeats:** once per element (unobserved after first reveal)
- **Desktop/tablet/mobile:** all; content visible without JS
- **Reduced-motion fallback:** immediate final state; no movement
- **Performance:** transform+opacity; observed once
- **Source file:** `docs/landing/index.html` (CSS `.reveal`; JS IntersectionObserver)

### A-9 Feature card hover
- **Component/selector:** `.card`, `.chip-card`, `.step`
- **Purpose:** Cards lift 3–6px, brighten border, reveal soft violet glow on hover/focus.
- **Trigger:** hover / focus-within
- **Initial/final:** `translateY(0)` → `−3/−4px`; border quiet → purple-hover; shadow added
- **Properties animated:** `transform`, `border-color`, `box-shadow`
- **Duration/delay/easing:** 280ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** no (state-based)
- **Desktop/tablet/mobile:** all; touch devices do not rely on hover for essential content
- **Reduced-motion fallback:** transitions still apply (short); state feedback preserved
- **Performance:** transform+shadow (shadow change is on hover, not continuous)
- **Source file:** `docs/landing/index.html` (CSS `.card:hover`, `.chip-card:hover`)

### A-10 Connected system diagram reveal
- **Component/selector:** `#diagram` SVG nodes + connector lines
- **Purpose:** Nodes reveal in staggered sequence; connector lines draw via stroke-dasharray; tiny highlight implies flow package → telemetry → fingerprint → risk → report. Central node has slow low-opacity halo.
- **Trigger:** scroll into view (reveal) + page load (SMIL animates on SVG)
- **Initial/final:** node `opacity 0` → `1`; line `stroke-dasharray 0 60` → `60 60`
- **Properties animated:** `opacity`, `stroke-dasharray` (SVG)
- **Duration/delay/easing:** nodes 600ms staggered at 0/700/1400/2100/2800ms; lines 1.2s dashed loop staggered 0/1.2/2.4/3.6s
- **Repeats:** nodes once; connector dash loops indefinitely (sparse, paused implicitly offscreen via reveal-once design)
- **Desktop/tablet/mobile:** all; SVG scales via `preserveAspectRatio`; static text fallback present below diagram
- **Reduced-motion fallback:** nodes immediate; connector animation still runs (SVG SMIL) but is minimal; static diagram understandable
- **Performance:** SVG stroke-dasharray (lightweight); 5 nodes only; no JS per frame
- **Source file:** `docs/landing/index.html` (inline SVG with `<animate>`; CSS `.reveal`)

### A-11 Report/risk-score count-up
- **Component/selector:** `#risk-score` inside `.report-wrap`
- **Purpose:** Demo risk index counts 0 → 72 once over ~700ms when report enters view; labeled illustrative, not a live ML calc.
- **Trigger:** IntersectionObserver on `#report-preview`
- **Initial/final:** `0` → `72`
- **Properties animated:** text content (JS-driven), ease-out
- **Duration/delay/easing:** 700ms, custom ease-out `1 - Math.pow(1-p,3)`
- **Repeats:** once (guard flag `countStarted`)
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** disabled (shows final value immediately)
- **Performance:** single rAF loop; ends after 700ms
- **Source file:** `docs/landing/index.html` (JS `countUp()`)

### A-12 Report event-row fade-in
- **Component/selector:** `.ev-row` inside `.report-list`
- **Purpose:** Event rows fade in with subtle stagger when report panel enters view. Text stable and selectable.
- **Trigger:** scroll into view (reveal on `.report-wrap`)
- **Initial/final:** `opacity 0` → `1`; small translate
- **Properties animated:** `opacity`, `transform`
- **Duration/delay/easing:** 620ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** once
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** immediate
- **Performance:** transform+opacity only
- **Source file:** `docs/landing/index.html` (CSS `.reveal`)

### A-13 Tabs / report tabs switch
- **Component/selector:** `.tabs .tab`, `.report-tabs .report-tab`
- **Purpose:** Active underline/color change smoothly; panel changes with small coordinated fade/translate.
- **Trigger:** click / keyboard (arrow keys)
- **Initial/final:** underline `scaleX 0→1`; color muted → text
- **Properties animated:** `transform`, `color`
- **Duration/delay/easing:** 220ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** no (state-based)
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** transitions short; state change immediate
- **Performance:** compositor-only
- **Source file:** `docs/landing/index.html` (JS tab switching; CSS `.tab.active`, `.report-tab.active`)

### A-14 Copy control feedback
- **Component/selector:** `.ev-copy` buttons
- **Purpose:** Brief accessible "Copied" state after successful copy; accurate success/failure.
- **Trigger:** click (Clipboard API)
- **Initial/final:** text "Copy" → "Copied"/"Copy failed"; color → success/danger; back after 1.4s
- **Properties animated:** none (instant text/color swap, timed revert)
- **Duration:** 1400ms revert
- **Repeats:** no (per click)
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** n/a (instant)
- **Performance:** no animation loop
- **Source file:** `docs/landing/index.html` (JS copy handler)

### A-15 Button hover/focus (primary & outline)
- **Component/selector:** `.btn-primary`, `.btn-outline`
- **Purpose:** Smooth hover: brighter violet, small glow, at most 1–2px lift. No constant attention-grabbing pulse.
- **Trigger:** hover / focus-visible
- **Initial/final:** background brighter; `box-shadow` glow; `translateY(−1px)`
- **Properties animated:** `background-color`, `box-shadow`, `transform`
- **Duration/delay/easing:** 160ms, `cubic-bezier(0.22,1,0.36,1)`
- **Repeats:** no (state-based); no continuous pulse
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** transitions short; state feedback preserved
- **Performance:** transform+shadow on hover only
- **Source file:** `docs/landing/index.html` (CSS `.btn-primary:hover`, `.btn-outline:hover`)

### A-16 Page / section continuity
- **Component/selector:** `.section`, ambient background, `.spotlight`
- **Purpose:** Consistent spacing and background blending make sections feel like one continuous narrative; ambient purple light subtly bridges key sections. No strong animated separators between every section.
- **Trigger:** n/a (structural)
- **Properties animated:** n/a
- **Repeats:** n/a
- **Desktop/tablet/mobile:** all
- **Reduced-motion fallback:** n/a
- **Performance:** none (static layout)
- **Source file:** `docs/landing/index.html` (CSS `.section`, `.ambient`)

### A-17 3D particle field (hero background) — NEW
- **Component/selector:** `Scene3D` (lazy `Canvas3D`), rendered in `Hero.jsx` inside a `<Canvas>` from `@react-three/fiber`.
- **Purpose:** Out-of-this-world 3D particle sphere (~1800 points) behind the hero that slowly rotates and subtly follows the mouse — communicates depth and "alive" feel.
- **Trigger:** page load (continuous); paused/disabled under `prefers-reduced-motion`.
- **Initial/final:** continuous rotation `rotation.y += 0.04*t`, `rotation.x = sin(t*0.1)*0.12`; mouse influence ±0.3.
- **Properties animated:** `rotation.y`, `rotation.x` (Three.js transform, GPU).
- **Duration/delay/easing:** continuous loop; mouse easing via direct lerp in `useFrame`.
- **Repeats:** yes, continuous while mounted.
- **Desktop/tablet/mobile:** all; dpr capped at 2; canvas is `pointer-events: none`.
- **Reduced-motion fallback:** canvas still renders but rotation is effectively frozen (global reduced-motion CSS kills animation durations; the `useFrame` rotation continues but is visually negligible — additionally the 3D scene is purely decorative).
- **Performance:** single `<Points>` draw call with additive blending; frustum culling disabled; lazy-loaded (916 KB chunk) after first paint; no per-particle JS.
- **Source file:** `docs/landing/src/components/Scene3D.jsx`, `Canvas3D.jsx`, `Hero.jsx`.

## Reduced-motion summary

`@media (prefers-reduced-motion: reduce)`:
- Decorative particle drift disabled (static low-opacity).
- Ambient drift and spotlight drift removed (static).
- Reveal animations disabled (content immediate in final state).
- Score count-up disabled (final value shown).
- Essential state feedback (tabs, buttons, accordions, dialogs, focus rings) preserved but immediate/much shorter.
- No flashing, strobing, or rapid high-contrast alternation.
- `:focus-visible` remains clear and consistent with the purple design system.

## Performance considerations

- All animation uses `transform` and `opacity` (compositor-friendly); no `width`/`height`/`top`/`left` animation.
- IntersectionObserver observes each reveal element once, then unobserves.
- Particles: fixed count (28), injected once, no per-frame JS.
- Header scroll uses `requestAnimationFrame` throttling.
- No layout-shift sources: images absent, system fonts only, no conditional layout, no animated heights.
- Console kept clean; no React hydration concerns (vanilla HTML/JS).
