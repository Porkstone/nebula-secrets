# Nebula Visual Style Guide

This guide describes the visual language used by Nebula Secrets so it can be
reused consistently in other applications. The current source of truth is
[`src/index.css`](src/index.css).

## 1. Design direction

Nebula uses a dark, security-focused interface with restrained sci-fi details.
It should feel calm, precise, and trustworthy rather than decorative.

The defining characteristics are:

- Deep blue-black application backgrounds.
- Translucent, blurred surfaces with fine teal borders.
- Teal as the default interactive accent.
- Violet and teal ambient gradients used sparingly in the background.
- Compact controls and information-dense layouts.
- Small uppercase labels for context and section metadata.
- Rounded corners that are soft, but not overly playful.
- Subtle glows used only for focus, active navigation, and status.
- A fully supported light theme that retains the dark sidebar.

## 2. Technology and conventions

- Use CSS custom properties for theme tokens.
- Apply the theme with `data-theme="dark"` or `data-theme="light"` on the
  document root.
- Use Lucide icons. Most interface icons should be `16px` to `20px`.
- Use semantic HTML first, then style reusable classes such as `.panel`,
  `.button`, `.notice`, and `.status-chip`.
- Tailwind is available, but the visual system is primarily expressed through
  named CSS classes and custom properties.
- Prefer `color-mix()` for derived borders and hover colors instead of adding
  isolated hard-coded colors.

## 3. Theme tokens

Dark mode is the default Nebula appearance.

```css
:root {
  color-scheme: dark;

  --ink: #e4f0f2;
  --ink-soft: #8ca2a8;
  --ink-faint: #58747b;

  --line: #17343b;
  --line-strong: #26474f;

  --surface: rgba(6, 19, 24, 0.91);
  --surface-solid: #07181d;
  --surface-soft: #061116;
  --surface-raised: #0a2026;

  --brand: #62d9d0;
  --brand-dark: #9af1e9;
  --brand-soft: rgba(60, 202, 193, 0.14);
  --brand-faint: rgba(54, 196, 187, 0.075);
  --brand-ring: rgba(98, 217, 208, 0.18);

  --danger: #da858a;
  --danger-soft: rgba(192, 72, 80, 0.14);
  --warning: #d0a26b;
  --warning-soft: rgba(191, 131, 61, 0.14);

  --shadow: 0 24px 70px rgba(0, 0, 0, 0.28);
  --app-background: #040c10;
  --sidebar-background: rgba(2, 11, 15, 0.96);
  --topbar-background: rgba(5, 17, 22, 0.78);
  --field-background: rgba(7, 24, 29, 0.88);

  --particle-bright: rgba(153, 246, 237, 0.48);
  --particle-soft: rgba(135, 120, 222, 0.26);
  --aurora-violet: rgba(95, 69, 177, 0.17);
  --aurora-teal: rgba(31, 189, 177, 0.09);
}
```

The light theme keeps the same hierarchy and replaces the surfaces and
foregrounds rather than redesigning components.

```css
:root[data-theme="light"] {
  color-scheme: light;

  --ink: #17292e;
  --ink-soft: #526a70;
  --ink-faint: #778c91;

  --line: #cfddde;
  --line-strong: #b8cdce;

  --surface: rgba(249, 252, 251, 0.9);
  --surface-solid: #f7fbfa;
  --surface-soft: #edf4f3;
  --surface-raised: #f4f9f8;

  --brand: #187f78;
  --brand-dark: #105f5a;
  --brand-soft: rgba(38, 143, 135, 0.12);
  --brand-faint: rgba(38, 143, 135, 0.065);
  --brand-ring: rgba(24, 127, 120, 0.15);

  --danger: #ad4f58;
  --danger-soft: #f9e9e9;
  --warning: #8e632f;
  --warning-soft: #f7eddf;

  --shadow: 0 20px 55px rgba(35, 65, 68, 0.11);
  --app-background: #eaf1f0;
  --sidebar-background: rgba(12, 29, 35, 0.97);
  --topbar-background: rgba(248, 252, 251, 0.82);
  --field-background: rgba(255, 255, 255, 0.75);

  --particle-bright: rgba(25, 123, 117, 0.25);
  --particle-soft: rgba(96, 76, 165, 0.15);
  --aurora-violet: rgba(115, 91, 189, 0.1);
  --aurora-teal: rgba(35, 155, 145, 0.08);
}
```

### Token usage

| Token              | Use                                                |
| ------------------ | -------------------------------------------------- |
| `--ink`            | Headings, primary text, and high-emphasis controls |
| `--ink-soft`       | Labels, supporting text, and inactive controls     |
| `--ink-faint`      | Metadata, timestamps, placeholders, and captions   |
| `--line`           | Normal dividers and component borders              |
| `--line-strong`    | Inputs, empty states, and stronger boundaries      |
| `--surface`        | Panels, lists, and glass-like content surfaces     |
| `--surface-solid`  | Modals and surfaces that require opacity           |
| `--surface-soft`   | Quiet backgrounds and nested regions               |
| `--surface-raised` | Inputs, buttons, table headers, and raised rows    |
| `--brand`          | Primary actions, active states, and key accents    |
| `--brand-dark`     | Brand-colored text with sufficient contrast        |
| `--brand-soft`     | Selected, informational, and icon backgrounds      |
| `--brand-faint`    | Hover washes and low-emphasis brand tint           |
| `--brand-ring`     | Focus rings and brand shadows                      |

Do not use brand colors for destructive or warning actions. Use the semantic
danger and warning tokens.

## 4. Typography

The interface uses a system-first sans-serif stack:

```css
font-family:
  Inter,
  ui-sans-serif,
  system-ui,
  -apple-system,
  BlinkMacSystemFont,
  "Segoe UI",
  sans-serif;
```

If Inter is not bundled by the consuming project, the system font is an
acceptable fallback.

### Type scale

| Element           | Size and treatment                                               |
| ----------------- | ---------------------------------------------------------------- |
| Page heading      | `clamp(1.65rem, 3vw, 2.2rem)`, weight `650`, tight tracking      |
| Section heading   | `1.28rem`, weight `650`                                          |
| Component heading | `0.95rem`                                                        |
| Standard body     | Approximately `0.78rem` to `0.84rem`, line-height `1.5` to `1.6` |
| Navigation        | `0.78rem`, weight `600`                                          |
| Labels            | `0.78rem`, weight `650`                                          |
| Metadata          | `0.61rem` to `0.7rem`, often uppercase                           |
| Eyebrow           | `0.76rem`, weight `700`, `0.08em` tracking, uppercase            |

Page headings and major section headings use approximately `-0.04em`
letter-spacing. Context labels use generous positive tracking and uppercase
text. Avoid uppercase for paragraphs, form labels, or button copy.

Monospaced content such as codes, fingerprints, or secret values uses:

```css
font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
```

## 5. Shape, spacing, and depth

Nebula uses compact spacing and a small family of radii:

| Purpose                 | Value                          |
| ----------------------- | ------------------------------ |
| Small control radius    | `9px`                          |
| Input or notice radius  | `10px`                         |
| Group/list radius       | `12px` to `14px`               |
| Panel radius            | `18px`                         |
| Modal radius            | `17px`                         |
| Pill or status radius   | `999px`                        |
| Standard control height | Approximately `34px` to `40px` |
| Main content width      | `min(1240px, 100%)`            |
| Desktop content padding | `clamp(1.4rem, 3vw, 2.4rem)`   |
| Mobile content padding  | `1rem`                         |

Use one-pixel borders even on translucent surfaces. Shadows should be broad and
soft. Avoid multiple strongly elevated elements in the same region.

## 6. Application shell

The desktop shell has a fixed-width sidebar, a sticky top bar, and a centered
content area.

```css
.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 238px minmax(0, 1fr);
}

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  z-index: 30;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  height: 72px;
  backdrop-filter: blur(20px) saturate(130%);
}

.workspace-main {
  width: min(1240px, 100%);
  margin: 0 auto;
  padding: clamp(1.4rem, 3vw, 2.4rem);
}
```

The sidebar remains dark in both themes. Navigation items are quiet by default,
gain a subtle teal wash on hover, and use a brighter teal foreground with a
two-pixel glowing marker when active.

Place the page title and short context text in the top bar. Inside the content
area, use a `.page-actions` row for the main heading, description, and primary
page action.

## 7. Background treatment

The background is layered rather than flat:

1. Start with `--app-background`.
2. Add a faint violet radial gradient near the upper-right corner.
3. Add a faint teal radial gradient near the bottom.
4. Optionally add a fixed particle field behind the application.

Particles are one-pixel radial gradients with very slow drift animations. They
must be decorative, use `pointer-events: none`, and sit behind all application
content. Keep their opacity low so text and controls remain dominant.

For simpler applications, use the two ambient radial gradients without the
particle layer.

## 8. Core components

### Panels

```css
.panel {
  color: var(--ink);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
}
```

Panels need internal padding supplied by their specific component. Typical
padding is `1.25rem`; larger setup or authentication panels use up to `2rem`.

### Buttons

All buttons use an inline-flex layout, a `9px` radius, compact padding, and bold
text.

- Default: raised surface with a strong border.
- Primary: solid brand background.
- Ghost: transparent background and border.
- Destructive: danger text and tint; becomes solid danger on hover.
- Icon-only: `34px` square with an accessible label or tooltip.
- Small: reduced padding and `0.75rem` text.

Use one primary button per action group. Put the primary action last when
buttons are arranged horizontally.

Example:

```tsx
<button className="button primary">
  <Plus size={17} />
  Create project
</button>

<button className="icon-button" aria-label="Edit project" title="Edit project">
  <Pencil size={16} />
</button>
```

### Form fields

Labels sit above controls and use soft foreground text with a `650` weight.
Inputs, selects, and text areas use:

```css
input,
select,
textarea {
  width: 100%;
  padding: 0.72rem 0.8rem;
  color: var(--ink);
  background: var(--field-background);
  border: 1px solid var(--line-strong);
  border-radius: 10px;
}

input:focus,
select:focus,
textarea:focus {
  border-color: var(--brand);
  box-shadow: 0 0 0 3px var(--brand-ring);
}
```

Do not remove the visible focus state. Help text belongs immediately below the
control in `--ink-faint`.

### Notices

Notices use an icon, concise text, a tinted semantic background, and a subtle
border.

- Success and informational notices use brand tokens.
- Errors use danger tokens.
- Warnings use warning tokens.
- Keep the icon aligned to the first text line.
- A dismiss button, if present, sits at the far edge.

### Status chips

Status chips are small pills using `0.65rem` bold text. Active or healthy states
include a five-pixel glowing dot. Muted chips use neutral raised surfaces.
Danger chips use danger tokens.

Status chips should describe state, not act as buttons.

### Lists and rows

Lists use a bordered surface with `12px` to `14px` rounded corners. Individual
rows are approximately `70px` high and separated by `--line`.

On hover, interactive rows receive a left-to-right gradient from
`--brand-faint` to transparent. Titles use primary text; type, version, or time
metadata uses `--ink-faint`.

### Empty states

Empty states use a dashed `--line-strong` border, centered content, and at least
`250px` to `360px` height. Include:

1. A softly tinted icon tile.
2. A concise heading.
3. One sentence explaining the state.
4. An optional single action.

### Modals

Modals use `--surface-solid`, a stronger border, and a heavier shadow than
normal panels. The backdrop is nearly black with blur.

- Standard width: `min(650px, 100%)`.
- Wide width: `min(790px, 100%)`.
- Maximum height: `min(88vh, 900px)`.
- Header and scrollable body are visually separated.
- On small screens, the modal becomes a bottom sheet with only its top corners
  rounded.

Use a full page instead of a modal for primary navigation destinations or
workflows that need significant space.

## 9. Contextual accent colors

Nebula can override brand tokens within a bounded page region to communicate
context while preserving all component styles.

| Context     | Dark accent | Light accent | Meaning                   |
| ----------- | ----------- | ------------ | ------------------------- |
| Local       | `#aa78d7`   | `#7440a5`    | Personal or machine-local |
| Development | `#55b878`   | `#287b45`    | Shared development        |
| UAT         | `#cf8248`   | `#a85321`    | Test or pre-production    |
| Production  | `#d06370`   | `#a83746`    | Live production           |

Apply the override to a container:

```html
<main class="workspace-main" data-environment="development">
  <!-- Existing components automatically inherit the green accent. -->
</main>
```

This pattern can be reused for workspaces, tenants, product areas, or workflow
states. Override the full brand family, not only `--brand`, so hover, focus,
border, and background treatments remain coherent.

## 10. Theme behavior

Persist the selected theme and apply it before or immediately after the
application mounts.

```ts
type Theme = "dark" | "light";

const savedTheme = localStorage.getItem("app-theme");
const theme: Theme =
  savedTheme === "light" || savedTheme === "dark" ? savedTheme : "dark";

document.documentElement.dataset.theme = theme;
```

The theme toggle is an icon-only control positioned in the top-right corner.
Use a sun icon in dark mode and a moon icon in light mode. Its accessible label
must describe the action, for example, “Switch to light mode.”

## 11. Responsive behavior

Nebula uses two primary breakpoints:

### At `900px` and below

- Collapse the two-column application shell to one column.
- Move the sidebar off-canvas.
- Reveal a menu button in the top bar.
- Slide the sidebar in when it has an `.open` class.
- Collapse multi-column setup and administration layouts.
- Simplify ambient background gradients.

### At `640px` and below

- Reduce the top bar to `62px`.
- Reduce main content padding to `1rem`.
- Hide secondary signed-in user metadata.
- Stack page headings and actions.
- Stack toolbars and multi-column forms.
- Allow segmented controls to scroll horizontally.
- Hide nonessential status chips in dense rows.
- Render modals as bottom sheets.

Do not make touch targets smaller than the existing `32px` to `40px` controls.

## 12. Motion

Use quick transitions of roughly `120ms` to `250ms` for hover, focus, theme,
and navigation changes. Background particle movement is deliberately very slow.

Always include reduced-motion support:

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    scroll-behavior: auto !important;
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
  }
}
```

## 13. Accessibility requirements

- Preserve semantic button, form, navigation, table, and heading elements.
- Give every icon-only button an `aria-label`; add `title` when helpful.
- Never communicate state through color alone. Pair color with text, an icon,
  or a status dot.
- Use the theme tokens instead of arbitrary colors so light and dark contrast
  remain predictable.
- Keep visible keyboard focus rings on all interactive controls.
- Mark purely decorative backgrounds and particles with `aria-hidden="true"`.
- Use an `.sr-only` utility for visually hidden accessible labels.
- Disable unavailable controls instead of only reducing their opacity.
- Respect `prefers-reduced-motion`.

## 14. Porting checklist

When applying Nebula styling to another project:

1. Copy the dark and light token sets.
2. Add the global font, box-sizing, foreground, and background rules.
3. Implement theme persistence with `data-theme`.
4. Add the application shell, sidebar, top bar, and content-width rules.
5. Port the reusable panel, button, form, notice, chip, empty-state, and modal
   classes.
6. Install Lucide and use consistent icon sizes.
7. Add the `900px`, `640px`, and reduced-motion media queries.
8. Add ambient gradients; add particles only if the product suits them.
9. Test every component in both themes and at mobile width.
10. Verify keyboard navigation, focus visibility, and contrast before release.

Product-specific names, secret types, environment labels, and security copy are
not part of the visual system and should be replaced by the consuming
application’s language.
