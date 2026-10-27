# MASTER PROMPT — Build the PS-1 Dependency Security Landing Page

You are acting as a senior product designer, design-systems engineer, frontend architect, motion designer, accessibility reviewer, and QA engineer. Your task is to build a polished, production-quality landing page for our cybersecurity project based on **PS-1: “Trust Nothing, Provenance for Your Own Dependencies.”** Use the supplied image and video files as design references, inspect the existing codebase before making changes, and implement the page in the existing stack.

Do not merely describe what you would build. Inspect the repository, make a plan, then execute it, validate the result, and document the design and motion system. Do not stop after generating a plan unless a genuine blocker prevents implementation.

---

## 0. Primary objective

Build a visually distinctive, responsive landing page that closely reproduces the **composition, dark visual atmosphere, spacing, card treatments, purple/indigo glow, product-showcase feel, section rhythm, and sophisticated motion** of the supplied references, while replacing the original product's messaging and UI with our real PS-1 dependency-security concept.

The page must feel deliberate, technically credible, and premium—not like a generic AI SaaS template. Maintain the reference's visual identity and section flow, but do not copy unrelated company names, logos, product claims, or text. Use original PS-1 copy and create our own security-product visual assets/components.

The finished output must include:
1. A complete landing page, not a static mockup.
2. Functional navigation and meaningful interactions.
3. A coherent, carefully tuned animation/transition system.
4. Responsive and accessible behavior.
5. Documentation of the visual system and every meaningful animation/transition.
6. A final validation summary describing what was implemented, what was tested, and any limitations.

## 1. Inspect the workspace before changing anything

First, inspect the existing project thoroughly:

- Identify the framework, build tool, package manager, routing setup, source structure, styling approach, existing design tokens, fonts, image assets, icon libraries, and animation libraries.
- Read the existing README and relevant configuration files.
- Identify the actual app entry point, global styles, page components, shared components, and existing tests.
- Search for the supplied reference files, matching names case-insensitively if necessary:
  - `Header_section.png`
  - `Section_below_header.mov`
  - `the_other_half.mov`
- Inspect the full duration of both recordings, not just a single frame. Sample key moments/sections and distinguish actual website UI from editor/terminal UI.
- Preserve existing conventions and working functionality. Do not replace the framework, restructure the entire application, or add dependencies without a clear reason.
- Do not claim to have inspected files, run commands, or passed tests unless you actually did so.

Before implementing, write a concise implementation plan into `docs/IMPLEMENTATION_PLAN.md` (or the repository's existing documentation location). Then proceed to implementation without waiting for confirmation, unless blocked by missing assets or a genuine technical issue.

## 2. Reference interpretation and visual hierarchy

Use these references with the following priority:

### A. `Header_section.png` — hero/header composition

Study and preserve the important visual structure:
- Oversized, bold, high-contrast headline.
- Compact, muted supporting copy beneath it.
- Deliberate line lengths and generous horizontal margins.
- A wide, rounded, thin-bordered interactive panel beneath the copy.
- A horizontal tab row with a clear active state and a thin underline/divider.
- Monospaced detail inside the panel, subdued secondary labels, and a copy/utility affordance where appropriate.
- Dark, quiet surfaces rather than colorful blocks everywhere.

Do not blindly copy the image's text about an AI coding agent or invent an install command for our security product. Reuse the layout pattern, but adapt the panel into a meaningful dependency-analysis/demo experience. If a command is shown, ensure it corresponds to a real command in this repository. If the CLI/backend does not exist, use a clearly labeled interactive product preview instead of a fake runnable command.

### B. `the_other_half.mov` — main visual language and page-section reference

Analyze the full video to reproduce the key design qualities:
- Near-black content surfaces surrounded by deep lavender/indigo atmosphere.
- Soft blue-violet light, sparse star-like particles, subtle specks, and restrained ambient glow.
- Large centered section headings with concise secondary descriptions.
- A floating product/dashboard preview that feels like a real interface, not a generic stock illustration.
- Wide, rounded feature/story panels with subtle borders, layered gradients, and restrained depth.
- A “problem/insight” banner with a small connected-node or incident-flow visual.
- A section that explains a unified platform through connected nodes feeding into a glowing central intelligence/security element.
- Asymmetric/staggered capability cards with different vertical positions and one restrained accent card.
- A lower-page CTA with a bright violet vertical spotlight/glow, clear heading, and one obvious action.
- Large areas of intentional negative space, carefully controlled density, and clear separation between sections.
- Subtle transitions between sections; avoid abrupt changes in background or card styling.

Reproduce the **design system and composition**, not the original brand. Replace any unrelated logo, company name, text, customer logos, incident-response content, and dashboard details with PS-1 equivalents. Do not display Resq.io or other unrelated brand identity as if it were our product.

The video appears to show a browser/page with a dark central surface and a purple/lavender ambient surround. Reproduce the atmospheric framing and central-page contrast if appropriate to the existing viewport, but do not create a fake browser window or device frame unless that is clearly part of the actual intended design.

### C. `Section_below_header.mov` — inspect carefully before interpreting

Inspect this recording fully. Sampled frames appear to show an OpenCode/editor coding session—including terminal output, test results, a prompt composer, and a side panel—rather than a website section screenshot. **Do not recreate an IDE/terminal UI as the landing page merely because it is visible in this recording.**

Determine whether the recording contains a separate website preview at any point. If it does, extract the actual webpage reference from those moments. If the file is entirely an editor/workflow recording, use it only for contextual information about the development process and rely on the other two assets for website styling. Document this ambiguity in `docs/REFERENCE_ANALYSIS.md` instead of making up a section that the file does not show.

### D. Resolve reference conflicts deliberately

- Use `Header_section.png` primarily for the hero structure and tabbed-panel interaction pattern.
- Use `the_other_half.mov` as the main source for the purple/indigo palette, downstream sections, cards, dashboard mockups, connected diagrams, atmospheric background and section transitions.
- Use actual package/product functionality and PS-1 content as the source of truth for copy and behaviors.
- If one reference conflicts with another, preserve the overall composition and hierarchy while using the visual style of `the_other_half.mov`.
- Create a short asset-by-asset interpretation in `docs/REFERENCE_ANALYSIS.md`, including uncertainty where the supplied files do not show something clearly.

## 3. The product and problem statement: PS-1

The product is a dependency-security analyzer for PyPI/npm-style packages. It investigates whether a package's observed behavior is consistent with its declared purpose.

The intended workflow is:
1. Identify a package/artifact and record its identity/version/hash.
2. Inspect its README and metadata to extract what it claims to do.
3. Run controlled install/build and import/test stages inside an isolated sandbox.
4. Observe relevant activity: file access, network attempts, environment-variable access where measurable, and subprocess creation.
5. Normalize observations into a behavioral fingerprint.
6. Compare expected capabilities with observed behavior and sequences.
7. Produce an explainable risk assessment and human-readable report.

Use this concept consistently in headings, diagrams, interface previews, cards, examples and CTA text. Make the security value understandable to a developer who is not a cybersecurity specialist.

### Suggested messaging (adapt it to fit the design)

**Hero headline:** “Know what your dependencies actually do.”

**Supporting copy:** “Observe install-time and import-time behavior. Compare it with declared intent. Get evidence-backed findings before a dependency earns your trust.”

**Primary CTA:** “Analyze a package”

**Secondary CTA:** “Explore how it works”

Possible eyebrow: “Behavior-first dependency security”

Possible section themes:
- “A package’s description is a claim—not proof.”
- “One fingerprint. Every important signal.”
- “From package install to evidence-backed decision.”
- “Suspicious behavior, explained.”
- “Trust should be earned at runtime.”

Suggested capability cards:
- Install-time and import-time observation.
- File and sensitive-path activity.
- Network and DNS attempts.
- Process/subprocess tracking.
- Behavioral sequence correlation.
- Declared intent versus observed behavior.
- Risk scoring with explicit evidence.
- Human-readable analysis reports.

Suggested high-level flow:
`Package → Isolated execution → Behavioral fingerprint → Intent comparison → Risk assessment → Explainable report`

Do not put every technical detail in the hero. The page should tell a coherent story, from the security problem to the analysis process and then the report/result.

### Accuracy constraints—mandatory

- Do not claim “100% detection,” perfect malware detection, zero false positives, or guaranteed safety.
- Distinguish an attempted action from a successful action. For example, say “attempted to read” if the sandbox blocked the read.
- Do not imply a sandbox is an absolute guarantee against all malicious behavior.
- Do not claim actual package execution, live analysis, ML accuracy, integrations, downloads, or cloud capabilities unless they exist in the repository.
- If the backend is not implemented, build a polished **clearly labeled demo/preview with deterministic sample data**. State that sample results are illustrative/simulated and do not scan a real package.
- Never show real secrets, credentials, or sensitive-looking data that could be mistaken for actual user data.
- Do not invent benchmarks, customer logos, security certifications, active customers, or supported ecosystems beyond what the current project genuinely supports.

## 4. Page structure and storytelling

Use the reference footage to inform the exact section rhythm, spacing and order. At minimum, build a complete page with the following narrative unless the existing project structure or reference evidence strongly suggests a better equivalent:

### Section 1 — Navigation and hero
- Lightweight top navigation with a distinctive text/icon mark, anchor links to major sections, and one primary CTA.
- Keep the nav elegant and compact; use the reference's dark palette and subtle border/blur treatment.
- Hero contains the main headline, supporting sentence, primary/secondary CTAs, and the wide tabbed panel or package-analysis preview inspired by `Header_section.png`.
- The hero preview should feel like a real security interface: package identifier, stage indicator, concise events, and a small sample status. Keep the first viewport readable and focused.

### Section 2 — Trust/technology strip
- Replace unrelated customer logos with relevant, honest capabilities or ecosystem labels, such as “Install-time analysis,” “Import-time analysis,” “Runtime evidence,” and “Explainable findings.”
- Do not imply endorsements or integrations that do not exist.

### Section 3 — The problem/insight banner
- Adapt the reference's “issues arise” visual into a compact statement about dependencies behaving differently from their claims.
- Show a small connected-node visual or a sequence of claim → observation → mismatch. Use restrained light, not a busy illustration.

### Section 4 — Unified dependency analysis
- Reinterpret the connected-node/central-AI diagram from the reference as a dependency-analysis flow.
- Nodes might represent metadata, sandbox, file activity, network activity, process events and intent comparison; connect them into a central “Behavioral fingerprint” or “Risk assessment” element.
- Make it legible at desktop, tablet and mobile. SVG/CSS diagrams are preferred when practical; avoid unneeded heavyweight images.

### Section 5 — Capability cards
- Use the reference's staggered/asymmetric card layout, subtle perspective and one controlled accent card.
- Include concise titles and plain-English descriptions for runtime observation, event correlation, mismatch detection, evidence capture and report generation.
- Ensure the layout remains understandable without animation.

### Section 6 — How it works
- Present a short, clear step-by-step process from package intake to the report.
- Use a timeline or connected steps, adapting the reference's connected visual language.
- Make install/build, import/function tests and the comparison/reporting stages distinct.

### Section 7 — Interactive report/product preview
- Show a believable package-analysis report with risk level, observed event list, evidence/why it matters, stage, outcome, and limitations.
- Use a small sample such as a fictional local string utility that attempted an unexpected sensitive-file read and network connection. Label the entire report “Illustrative sample” or “Demo data.”
- Clearly show “blocked” versus “succeeded” where relevant.
- A score may be shown as a **demo risk index**, not a calibrated probability of malware, unless a real calibrated model exists.

### Section 8 — Final CTA
- Follow the reference's dramatic but restrained purple spotlight/ambient beam treatment.
- Use a concise ending like “Verify behavior before you trust the dependency.”
- CTA must work: scroll to the demo, open the actual implemented analysis flow, or navigate to an existing working route. Never leave a dead button.

### Footer
- Compact, understated footer with project name, working section links and only real repository/documentation/social links. Do not invent external URLs.

## 5. Visual design system

Create a consistent set of design tokens and use them throughout. The following colors are suggested starting values based on the reference; sample the supplied footage more accurately if your tooling allows and adjust them consistently:

- `--color-bg`: `#07070B` (near-black main canvas)
- `--color-bg-raised`: `#101018` (raised surfaces)
- `--color-card`: `#12121D` (cards)
- `--color-purple`: `#5A4BFF` (primary violet)
- `--color-purple-bright`: `#7769FF` (active/glow accent)
- `--color-lavender`: `#AAA2FF` (soft highlight)
- `--color-blue-lilac`: `#AFC0FF` (secondary light accent)
- `--color-text`: `#F6F5FF` (primary text)
- `--color-text-muted`: `#AAA8BA` (secondary text)
- `--color-text-subtle`: `#777487` (tertiary text)
- `--color-border`: `rgba(204, 196, 255, 0.14)` (quiet surface border)
- `--color-glow`: `rgba(104, 83, 255, 0.28)` (ambient light)

Guidelines:
- The primary canvas should remain near-black. Purple/lavender belongs in light, selected states, gradients, diagrams, active cards and CTA—not in every background.
- Use one coherent radius scale (for example, 12px / 18px / 26px) rather than random corner radii.
- Use a consistent spacing scale and generous section padding. Desktop should feel spacious; mobile should be deliberate, not cramped.
- Use strong typographic hierarchy: high-impact headline, readable body text, precise muted labels, restrained monospaced metadata.
- Prefer a crisp, readable sans-serif for normal copy and a carefully selected mono face for code/telemetry. Reuse repository fonts if already configured; otherwise use robust system fallbacks or an already-present font provider. Do not introduce layout shift from late-loading fonts.
- Cards should use subtle border contrast, layered surface gradients and carefully controlled shadows. Avoid thick outlines, too many gradient fills, excessive glassmorphism or overuse of neon.
- Use consistent icon style from the project's current icon library if available. Do not mix emojis with line icons for product UI.
- Do not use generic stock photos. Build the product story from UI mockups, diagrams, typography and abstract ambient light.
- Use CSS/SVG/HTML for visuals wherever possible. Keep all imagery intentional and appropriately optimized.

## 6. Sophisticated animation and transition system — high priority

Motion is a core part of the brief, not a finishing touch. Design a cohesive motion language and implement it deliberately. Motion should make the page feel refined, spatial and alive—never chaotic, distracting, slow or difficult to read.

### 6.1 Motion principles

- Use motion to communicate hierarchy, connection, state changes and depth.
- Prefer restrained opacity/transform animation over animating layout properties.
- Avoid gratuitous animation on every element, perpetual strong pulsing, excessive parallax, aggressive 3D rotation, scroll-jacking, or transitions that delay the user.
- Every repeated animation must have a reason and a defined speed.
- Keep motion smooth on mid-range devices. Prefer compositor-friendly `transform` and `opacity`; avoid continuous blur filters, large animated shadows, expensive canvas loops or repeated React state updates on every animation frame.
- Avoid content jumping or layout shifts when animations start.
- Animations must not be necessary to understand content or complete an interaction.
- Use a restrained violet/lavender glow language inspired by `the_other_half.mov`.

### 6.2 Define global motion tokens

Create shared CSS variables or a central motion configuration, matched to the existing stack. Start with these values and adjust only if the reference justifies it:

- `--motion-fast`: `160ms` (small hover/focus response)
- `--motion-ui`: `220ms` (tabs, buttons, toggles, nav states)
- `--motion-card`: `280ms` (card hover and small depth changes)
- `--motion-reveal`: `620ms` (section entrances)
- `--motion-feature`: `760ms` (larger hero/diagram entrances)
- `--ease-standard`: `cubic-bezier(0.22, 1, 0.36, 1)` (soft, confident entrance)
- `--ease-emphasized`: `cubic-bezier(0.16, 1, 0.3, 1)` (hero/feature reveal)
- `--ease-exit`: `cubic-bezier(0.4, 0, 1, 1)` (exit/fade away)
- Use a consistent small stagger, generally `50–100ms`, rather than random delays.

Do not sprinkle unrelated durations and easing curves across components. If using Framer Motion or another library already installed, define shared variants/tokens; otherwise use CSS transitions/keyframes and IntersectionObserver where appropriate. Do not add an animation library just for one effect.

### 6.3 Required motion treatments

Implement the following where they fit the reference and page structure:

**A. Ambient background**
- A layered radial-gradient field with deep violet/blue light behind the black canvas.
- Sparse tiny particles/stars may drift or softly twinkle at low opacity. Keep their density low and speed slow (roughly 14–28 seconds per loop).
- A broad soft light beam behind the CTA can drift very slowly; use gradients or a lightweight pseudo-element rather than a huge animated blur filter.
- Keep the background fixed or subtly positioned without causing scroll lag. Do not reduce text contrast.
- On mobile and reduced-motion devices, reduce the particle count or render a static texture.

**B. Hero entrance**
- Animate the eyebrow, headline, supporting copy, CTAs and analysis panel in an intentional sequence.
- Use a short fade/vertical reveal with a small travel distance (roughly 10–22px). Headline lines may stagger very slightly, but do not animate each character unless the reference unmistakably calls for it.
- The main panel can appear a little later with a subtle opacity/translate/scale transition. It must not visibly jump into its final layout.
- The complete hero must be readable immediately and must not make users wait for the message.

**C. Navigation**
- Navigation links get a fast color/opacity change and a subtle underline or glow on hover/active state.
- If sticky navigation exists, when the page scrolls it may gain a slightly stronger translucent background and border. Keep the transition smooth and avoid changing its height.
- Mobile menu open/close should animate opacity and transform, manage focus correctly, and close with Escape. It must not trap focus unless it is implemented as a true modal drawer.

**D. Scroll-triggered section reveals**
- Sections, headings, body text and visual panels can reveal on first entry into view using `IntersectionObserver` or the current motion library.
- Use opacity plus a small translate; optionally use a subtle scale from about `0.985` to `1` for large panels.
- Reveal once by default rather than replaying every time the user scrolls up and down. Use consistent stagger groups (about 60–90ms).
- If JavaScript is unavailable or motion is reduced, content must still be fully visible.
- Do not hide the entire page waiting for a script to initialize.

**E. Feature cards**
- On hover/focus, cards may lift by approximately 3–6px, brighten their border and reveal a soft violet glow.
- Keep the effect restrained; do not tilt cards dramatically or make their layout shift.
- Use the same timing and easing for all comparable cards.
- The accent card can have a slightly stronger edge or gradient, but should not pulse continuously.
- On touch devices, do not rely on hover to reveal essential content.

**F. Connected system/behavior diagram**
- Reveal the nodes in a short staggered sequence.
- Draw connector lines using SVG stroke-dashoffset or a similarly lightweight effect.
- A tiny highlight may travel along one or two edges to communicate flow from package → telemetry → fingerprint → risk finding. Keep the continuous motion sparse and pause/disable it when offscreen if practical.
- The central security/analysis node can have a slow, low-opacity halo, not a bright blinking beacon.
- Provide a fully visible static diagram as the fallback. The diagram must remain understandable on mobile, even if rearranged vertically.

**G. Report/risk-score preview**
- Use short state transitions for tabs, event rows, filters, expand/collapse controls and severity badges.
- When a sample report enters view, the score may count up once from a low value to its demo value over about 600–900ms; do not imply a live ML calculation if the data is static.
- Event rows may fade in with a subtle stagger. Keep the text stable and selectable.
- Label results as demo/illustrative unless connected to a real backend.

**H. CTA and spotlight**
- Use the reference's purple spotlight/glow as a soft backdrop with a slow gradient drift, around 18–30 seconds per loop if animated.
- Button hover/focus should transition smoothly: slightly brighter violet, a small glow, and at most a 1–2px lift.
- Avoid a constant attention-grabbing pulse on the primary button. A subtle idle luminance shift is optional only if it remains nearly imperceptible.

**I. Tabs, accordions, copy controls and dialogs**
- Tabs should update active underline/color smoothly and change the panel with a small, coordinated fade/translate.
- Accordion content should open/close without clipping text or causing a sudden large jump. If animating height is awkward in the existing stack, use a suitable grid-row or measured-height technique; do not use a fixed height that truncates content.
- Copy controls must show a brief, accessible “Copied” state after a successful copy. Do not claim copy success if the clipboard API fails.
- Dialogs should animate opacity and small scale, close using Escape and restore focus to the trigger.

**J. Page/section continuity**
- Use consistent spacing and background blending to make sections feel like one continuous product narrative.
- Avoid strong animated separators between every section. Let ambient purple light subtly bridge key sections.
- If using route transitions, keep them quick and never block navigation. Do not implement elaborate route animation for a single-page site unless there is a real need.

### 6.4 Accessibility and reduced motion

- Implement `@media (prefers-reduced-motion: reduce)` throughout the animation system.
- Reduced motion should disable decorative particle drift, beam motion, parallax, animated connector pulses, score counting and nonessential reveal movement. Present content immediately in its final state.
- Preserve essential state feedback for tabs, buttons, accordions and dialogs, but make transitions immediate or much shorter.
- Do not flash, strobe or rapidly alternate high-contrast colors.
- Respect keyboard focus. `:focus-visible` must be clear and visually consistent with the purple design system.
- Check that animated elements do not cover text, hide focus rings, cause horizontal overflow or shift layout unexpectedly.

## 7. Functional interaction requirements

Every visible interactive control must do something real and coherent. No dead buttons, fake links, placeholder clicks or controls that are only decorative.

- Navigation links scroll to their corresponding sections or use existing routes.
- The hero panel should have purposeful tabs, such as “PyPI”, “npm” and “Local package”, only if that mapping makes sense for the implemented demo. Selecting a tab must actually change the panel content.
- If a package name/upload/scan interaction is displayed but no backend exists, implement a clearly labeled sample/demo flow with deterministic fixtures. It must not silently execute arbitrary packages or imply a real scan occurred.
- If there is an existing backend or API in the repository, inspect and integrate it using the existing conventions; do not invent endpoint paths.
- The analysis-preview UI should include coherent example stages and events; sample records must be clearly marked as simulated.
- Buttons such as “Analyze a package,” “Explore how it works,” and the final CTA must scroll to, open or trigger the relevant working interface.
- Copy buttons must use the actual displayed text and report success/failure accurately.
- Mobile navigation must work with touch and keyboard.
- Do not fabricate installation commands, supported integrations, analysis results, package badges or external destinations.

## 8. Responsive design

Test at a minimum of these viewport widths: `360`, `390`, `768`, `1024`, `1440`, and `1920` pixels.

- Desktop: preserve the reference's large typography, wide panels, balanced negative space and layered card layouts.
- Tablet: reduce gutters and gaps gradually; prevent the connected diagram and staggered cards from colliding.
- Mobile: use a clean single-column hierarchy; reduce headline size fluidly; stack CTAs when needed; transform multi-column cards and diagrams into readable vertical layouts; keep code/event text from overflowing.
- Use `clamp()` or an equivalent fluid type/spacing strategy where appropriate.
- Avoid horizontal scrolling, cut-off headings, fixed-width cards, tiny text and controls too close together.
- Ensure all key product content remains readable even when decorative visuals and motion are disabled.

## 9. Accessibility, semantics and performance

- Use semantic landmarks, logical heading order, descriptive button/link text and accessible labels.
- Ensure keyboard usability and visible focus states.
- Maintain readable contrast for muted body text, code, borders and status badges.
- Use ARIA only when necessary; prefer native semantic HTML controls.
- For animated or diagrammatic content, provide an understandable text equivalent where appropriate.
- Respect `prefers-reduced-motion` and `prefers-color-scheme` only if consistent with the project requirements; the intended design is dark by default.
- Optimize assets and avoid massive inline SVGs, unnecessary libraries, heavy video backgrounds or unbounded animation loops.
- Pause expensive or nonessential offscreen animation when practical.
- Avoid layout shift from images, fonts, conditional rendering or animated heights.
- Keep console output clean; address React key warnings, hydration issues and accessibility warnings where applicable.
- Do not compromise semantic structure just to achieve a visual effect.

## 10. Documentation requirements

Create or update these files, following existing repository documentation conventions. Do not scatter inconsistent notes across multiple locations.

### `docs/REFERENCE_ANALYSIS.md`
Include:
- Which details came from each supplied asset.
- The page composition and palette interpretation.
- Which items were adapted rather than copied.
- The ambiguity that `Section_below_header.mov` appears to show a coding-agent/editor session in sampled frames, if the full recording confirms this.
- Any visual details that cannot be established confidently from the references.

### `docs/DESIGN_SYSTEM.md`
Document:
- Color tokens and their intended roles.
- Typography scale and font choices/fallbacks.
- Spacing scale, max-widths and responsive gutters.
- Border, radius, shadow and glow tokens.
- Icon rules, surface treatments and component variants.
- Responsive breakpoints or fluid sizing rules.

### `docs/ANIMATIONS.md` — mandatory and detailed
Document **every meaningful animation and transition implemented**, not just broad principles. For each animation, include:
- Unique ID/name.
- Component/selector where it lives.
- Purpose and user-visible effect.
- Trigger (page load, hover, focus, click, scroll into view, tab change, etc.).
- Initial and final states.
- Properties animated (transform, opacity, border color, gradient position, SVG stroke, etc.).
- Duration, delay/stagger and easing token.
- Whether it repeats; loop duration and stopping/pause behavior if applicable.
- Desktop/tablet/mobile behavior.
- Reduced-motion fallback.
- Performance considerations.
- Source file/component implementing it.

Include a compact motion-token table, an interaction-state table, and a checklist confirming that every animation uses the shared system. Update this document whenever an animation is changed.

### `docs/IMPLEMENTATION_PLAN.md`
Record the inspection findings, phases, completed work, validation steps, and any remaining limitations. Keep it accurate as implementation proceeds.

### `docs/QA_CHECKLIST.md`
Record responsive, accessibility, functional-interaction, animation/reduced-motion and browser-console checks. Mark only tests actually completed as passed.

## 11. Implementation workflow

Work in these phases:

**Phase 1 — Discover**
Inspect the repository, dependencies, asset files, and reference clips. Identify what already works and what is missing.

**Phase 2 — Plan and document the design interpretation**
Write the implementation plan, reference analysis, a concise section outline, and design-token proposal. Do not get stuck endlessly planning; move into implementation.

**Phase 3 — Build layout and core visuals**
Implement navigation, hero, product preview, subsequent sections, CTA and footer. Match the visual hierarchy and colors before adding elaborate motion.

**Phase 4 — Add interaction and motion**
Implement functional states, shared motion tokens, section reveals, card hovers, connected diagram motion, report-preview transitions, CTA glow and reduced-motion handling. Document each as it is introduced.

**Phase 5 — Refine**
Compare screenshots at multiple sizes with the supplied references. Tune typography, spacing, line length, gradients, shadows, card placement, border contrast and animation pacing. Remove anything generic, excessive or inconsistent.

**Phase 6 — Validate**
Run the actual available lint, type-check, build and tests. Open the application if tooling allows. Inspect console errors and screenshots at required widths. Test keyboard navigation, mobile menu, all tabs/buttons, sample/demo labeling, and reduced-motion mode.

**Phase 7 — Report**
Summarize changed files, important design decisions, animation inventory, commands/tests actually run, known limitations, and how to launch the page. Do not claim success for untested behavior.

## 12. Definition of done / acceptance criteria

The task is complete only when all feasible criteria below are satisfied:

- [ ] The existing project is preserved and the implementation uses its current stack.
- [ ] The hero follows the composition of `Header_section.png`, adapted to the PS-1 product.
- [ ] The overall palette, visual language, section hierarchy, card layouts, product showcase and CTA atmosphere follow `the_other_half.mov`.
- [ ] `Section_below_header.mov` has been inspected fully and interpreted honestly rather than blindly copied as a webpage if it is actually an editor recording.
- [ ] Copy accurately explains dependency-behavior analysis and avoids unsupported security claims.
- [ ] The page presents a coherent journey from problem → monitoring/fingerprint → intent comparison → risk/report → CTA.
- [ ] The main interactions actually work, and simulated results are labeled.
- [ ] Motion is coherent, premium, responsive, lightweight and accessible.
- [ ] `prefers-reduced-motion` is honored across decorative animations and reveals.
- [ ] No horizontal overflow, broken links, dead buttons, unreadable text or visible layout jumps remain at tested widths.
- [ ] The design system and every implemented animation/transition are documented in the required docs.
- [ ] Available checks have been run and their actual results are reported honestly.

## Final instruction

Prioritize **visual fidelity, security-domain accuracy, sophisticated but restrained motion, real interaction behavior, accessibility and implementation quality** equally. Do not settle for a generic landing page, a screenshot-like static page, or animations added without a documented system. Inspect first, plan briefly, build fully, compare against the references, refine, test, and document the finished result.
