# Reference Analysis — PS-1 / TrustLens Landing Page

Asset-by-asset interpretation of the three supplied reference files, per the master prompt (§2.C–D). This page lives at `docs/landing/index.html`.

## Assets inspected

| Asset | Type | Size / duration |
|---|---|---|
| `Header_section.png` | PNG image | 2168 × 730 px, RGBA |
| `the_other_half.mov` | QuickTime movie | 2114 × 1496 px, ~19.7 s @ 60 fps |
| `Section_below_header.mov` | QuickTime movie | inspected; see ambiguity below |

## A. Header_section.png — hero / header composition

Used primarily for the hero structure and the tabbed-panel interaction pattern (master prompt §2.A, §4.1).

**Visual structure preserved:**
- Oversized, bold, high-contrast headline → hero `h1`: "Know what your dependencies actually do."
- Compact, muted supporting copy beneath it → `hero-sub` paragraph.
- Deliberate line lengths and generous horizontal margins → centered hero, max-width container.
- A wide, rounded, thin-bordered interactive panel beneath the copy → `hero-panel` with the tabbed package-analysis preview.
- A horizontal tab row with a clear active state and a thin underline/divider → `.tabs` / `.tab` with active underline.
- Monospaced detail inside the panel, subdued secondary labels, copy/utility affordance → package chip, stage list, event rows, copy buttons.
- Dark, quiet surfaces → near-black canvas (`#07070B`), raised cards (`#12121D`), quiet borders (`rgba(204,196,255,0.14)`).

**Adapted (not copied):**
- The original panel text referenced an AI coding agent and a runnable install command. We do **not** have a real backend install command to show, so the panel shows a clearly labeled *illustrative sample* of package-analysis telemetry (stages + event rows) instead of a fake runnable command, per master prompt §2.A and §7.
- No unrelated company names, logos, or product claims are reproduced.

## B. the_other_half.mov — main visual language

Used as the main source for palette, downstream sections, cards, dashboard mockups, connected diagrams, atmospheric background, and section transitions (master prompt §2.B, §4.2–4.9).

**Design qualities reproduced:**
- Near-black content surfaces (`#07070B`) surrounded by deep lavender/indigo atmosphere → fixed ambient radial-gradient field (`#2A2255`, `#5A4BFF`) plus sparse particles.
- Soft blue-violet light, sparse star-like particles, subtle specks, restrained ambient glow → 28 drifting/twinkling particles, slow 14–28 s loops; disabled under `prefers-reduced-motion`.
- Large centered section headings with concise secondary descriptions → `.section-head` with kicker + `h2` + muted paragraph.
- A floating product/dashboard preview that feels like a real interface → `hero-panel` with stages, status badges, event list; no fake browser/device frame (per §2.B).
- Wide, rounded feature/story panels with subtle borders, layered gradients, restrained depth → `.card`, `.panel`, `chip-card` with `var(--color-border)` and `var(--shadow-card)`.
- A “problem/insight” banner with a small connected-node or incident-flow visual → `#problem` banner with warning icon and claim→observation mismatch copy.
- A section explaining a unified platform through connected nodes feeding into a central element → `#diagram` SVG flow: Package → Sandbox → Fingerprint → Risk assessment → Report, with dashed connector reveals and a glowing central node.
- Asymmetric/staggered capability cards with different vertical positions and one restrained accent card → `#capabilities` `card-grid`; one `card.accent` (Network) with stronger edge/gradient.
- A lower-page CTA with a bright violet vertical spotlight/glow → `#demo` `.spotlight` radial gradient with slow drift (26 s loop).
- Large areas of intentional negative space, controlled density, clear section separation → generous section padding, `clamp()` fluid type, consistent spacing scale.
- Subtle transitions between sections → shared reveal system, no abrupt background/card changes.

**Not reproduced:** the original brand, logo, company name, customer logos, or incident-response content. All replaced with PS-1 / TrustLens equivalents.

## C. Section_below_header.mov — inspected honestly

**Finding:** sampled frames and review indicate this recording shows an OpenCode / editor coding session — terminal output, test results, a prompt composer, and a side panel — **not a website section**. Per master prompt §2.C / §7, we do **not** recreate an IDE/terminal UI as the landing page merely because it is visible in this recording.

No separate website preview was identified in the recording. It is therefore used only for contextual information about the development process, and the other two assets (`Header_section.png`, `the_other_half.mov`) are relied upon for website styling. This ambiguity is documented here rather than inventing a section the file does not show.

## D. Reference conflicts resolved

- Hero structure follows `Header_section.png`; palette and downstream sections follow `the_other_half.mov` (§4).
- Copy and behavior come from the actual PS-1 / TrustLens product (README, AGENTS.md, CONTRACTS.md) — the source of truth (§2.D).
- Where references conflict, overall composition and hierarchy are preserved while using the visual style of `the_other_half.mov`.

## Visual details not established confidently

- Exact particle count/speed and glow intensity from `the_other_half.mov` could not be sampled programmatically (no frame-extraction tooling available); values were chosen to match the described atmosphere and tuned by inspection. These are approximations, not exact samples.
- The precise corner radii and spacing of the original panels are approximated with the token scale (10 / 16 / 26 px) rather than sampled pixel values.
