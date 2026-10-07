# Exposure Page Overrides

> **PROJECT:** Scantrely
> **Generated:** 2026-10-07
> **Page Type:** Search-first OSINT dashboard

> Rules here override Master (`design-system/scantrely/MASTER.md`) for the
> infostealer exposure workspace and the company Exposure tab.

---

## Page-Specific Rules

### Layout

- Search-first hero: labeled query field, 44px submit, helper text under the field.
- KPI grid: 2 columns on small screens, 4 on desktop (`min-width: 900px`).
- Family ranking uses labeled horizontal bars (name + count). Color is a hint, not the only encoding.

### Content

- Product name stays Scantrely. Source footnote: Hudson Rock Cavalier (OSINT público).
- Skip redacted `*****` URLs. Never render `malware_path`.
- Empty state always includes a next action (try a company domain).

### Motion

- Follow Master `--motion` / reduced-motion. Bars size by width only; no animation required.
