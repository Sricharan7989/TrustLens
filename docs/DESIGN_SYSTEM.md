# Design System — TrustLens / PS-1 Landing Page

Source: `docs/landing/index.html` (embedded `<style>`). Single self-contained HTML file; no build step, no external assets, no late-loading fonts.

## Color tokens

| Token | Value | Role |
|---|---|---|
| `--color-bg` | `#07070B` | Near-black main canvas |
| `--color-bg-raised` | `#101018` | Raised surfaces |
| `--color-card` | `#12121D` | Cards |
| `--color-card-active` | `#181824` | Hovered card surface |
| `--color-purple` | `#5A4BFF` | Primary violet |
| `--color-purple-bright` | `#7769FF` | Active / glow accent |
| `--color-purple-dim` | `#3A2ED8` | Darker violet variant |
| `--color-lavender` | `#AAA2FF` | Soft highlight |
| `--color-blue-lilac` | `#AFC0FF` | Secondary light accent |
| `--color-indigo-deep` | `#2A2255` | Ambient background depth |
| `--color-text` | `#F6F5FF` | Primary text |
| `--color-text-muted` | `#AAA8BA` | Secondary text |
| `--color-text-subtle` | `#777487` | Tertiary text |
| `--color-text-inverse` | `#07070B` | Text on bright accents |
| `--color-success` | `#34C759` | Positive / completed state |
| `--color-warn` | `#F2B03C` | Caution / review |
| `--color-danger` | `#FF4D6D` | Blocked / critical |
| `--color-border` | `rgba(204,196,255,0.14)` | Quiet surface border |
| `--color-border-hover` | `rgba(90,75,255,0.45)` | Hovered border |
| `--color-glow` | `rgba(104,83,255,0.28)` | Ambient light |
| `--color-glow-strong` | `rgba(90,75,255,0.55)` | Stronger glow |
| `--color-shadow` | `rgba(0,0,0,0.55)` | Drop-shadow base |
| `--color-surface-code` | `#0B0B12` | Code / chip surface |

Guideline: primary canvas stays near-black. Purple/lavender appears in light, selected states, gradients, diagrams, active cards, and CTA — not in every background.

## Radius tokens

| Token | Value | Use |
|---|---|---|
| `--radius-sm` | `10px` | Chips, small badges |
| `--radius-md` | `16px` | Cards, panels, event rows |
| `--radius-lg` | `26px` | Hero panel, large surfaces |
| `--radius-full` | `9999px` | Buttons, pills |

## Spacing scale

| Token | Value |
|---|---|
| `--space-xs` | `8px` |
| `--space-sm` | `14px` |
| `--space-md` | `22px` |
| `--space-lg` | `36px` |
| `--space-xl` | `56px` |

Sections use `var(--space-xl)` vertical padding; containers max-width `1200px` with `var(--space-md)` side padding.

## Shadows & borders

- `--shadow-card`: `0 10px 30px -10px rgba(0,0,0,0.55)`
- `--shadow-glow`: `0 0 40px -12px rgba(104,83,255,0.28)`
- `--shadow-elevated`: `0 20px 50px -14px rgba(0,0,0,0.55)`
- Cards use subtle `1px` borders in `var(--color-border)`; hover brightens to `var(--color-border-hover)`.

## Typography

- Sans: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif` (`--font-sans`)
- Mono: `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace` (`--font-mono`)
- `--line-tight`: `1.15` (headings)
- `--line-normal`: `1.55` (body)
- Fluid type via `clamp()`: hero `h1` `clamp(2.4rem, 4.2vw, 4.2rem)`, section `h2` `clamp(1.75rem, 2.5vw, 2.5rem)`, body `clamp(1rem, 1.2vw, 1.125rem)`.

No web fonts are loaded, so there is no font-related layout shift.

## Component variants

- `.btn` / `.btn-primary` (filled violet) / `.btn-outline` (bordered)
- `.card` / `.card.accent` (one restrained accent card)
- `.tab` / `.tab.active`
- `.report-tab` / `.report-tab.active`
- `.chip-card` (trust strip)
- `.step` (how-it-works)
- `.ev-chip` variants: `net`, `fs`, `proc`, `env`, `finding`

## Responsive breakpoints

Single breakpoint at `768px`:
- Desktop: large typography, wide panels, two-column panel body, multi-column card/step grids.
- Mobile (≤768px): single-column grids, stacked hero actions, stacked CTAs, mobile drawer menu, fluid headline scaling.

Fluid `clamp()` typography covers intermediate sizes; tested widths: 360, 390, 768, 1024, 1440, 1920 px.

## Icon rules

- Inline SVG only for the brand mark; no emojis mixed with line icons for product UI.
- Capability chips in the trust strip use Unicode symbols (`🔍`, `🗂️`, `🌐`, `🛠️`, `🔗`, `📄`) as decorative icons with adjacent text — never as the sole means of conveying meaning.
- No generic stock photos; visuals are UI mockups, diagrams, typography, and abstract ambient light.

## Surface treatment

- Cards: subtle border contrast, layered surface gradients (`linear-gradient(180deg, ...)`), controlled shadows. No thick outlines, excessive gradient fills, heavy glassmorphism, or overuse of neon.
- Background: fixed ambient radial field; particles at low opacity; CTA spotlight pseudo-element; no layout shift from images/fonts.
