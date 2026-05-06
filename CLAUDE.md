# CLAUDE.md — CATCH-Tool Project Instructions

This file is read automatically by Claude Code at the start of every session in this repo.

---

## Project Overview

**CATCH — Contract & Schema Triage Hub**
Browser-based diagnostic tool for court data submission validation.
Owner: Bryce Beltran · BIS TPM · Tyler Technologies Courts & Justice

**Stack:** Vanilla HTML + CSS + JavaScript — no npm, no build toolchain, no package.json.
**Deploy:** Azure Static Web Apps (free tier) via GitHub Actions. Every push to `main` auto-deploys in ~2 minutes.

---

## File Map

| File | Purpose |
|---|---|
| `index.html` | Main app — all UI, tabs, and inline structure |
| `styles.css` | All styling |
| `app.js` | Core validation logic |
| `tx-workbook-schema-v3.js` | Embedded TX OCA schema data |
| `Schema_v3.0.0_APPROVED.xlsx` | Reference schema workbook (not deployed) |
| `.github/workflows/` | Azure Static Web Apps auto-deploy config |
| `Docs/` | Full documentation set |

---

## Critical Rules

- **Never commit or push without explicit user approval** — always show a summary and ask first
- **Never push directly** — ask separately after committing
- `CATCH-admin.html` must **never** be deployed or committed — confirm it is absent from the repo and the GitHub Actions deploy path before any push
- No `package.json` — do NOT run npm, yarn, or any Node commands
- Changes to `tx-workbook-schema-v3.js` or schema data require extra care — flag these for user review before staging

---

## Standard Maintenance Workflow

When asked to "check", "audit", "scan", "review", or "maintain" the repo:

1. **Verify file inventory** — confirm expected files are present; flag anything unexpected
2. **Check CDN dependency** — verify `xlsx-js-style@1.2.0` in `index.html` is still the latest version
3. **Check cache-bust version strings** — `?v=YYYYMMDD` suffix on `app.js`, `styles.css`, and `tx-workbook-schema-v3.js` should be consistent and current
4. **Review GitHub Actions workflow** — confirm deploy target is `main`, no secrets exposed, workflow is valid YAML
5. **Scan for console errors / JS issues** — look for obvious syntax errors, undefined references, or broken logic in `app.js`
6. **Check for sensitive data** — confirm no API keys, credentials, internal URLs, or PII in any committed file
7. **Confirm admin file is absent** — `CATCH-admin.html` should NOT be in the repo
8. **Present health report** — summarize findings before any git action
9. **Commit** — ask for approval, show proposed message, then commit only after yes
10. **Push** — ask again separately before pushing to origin

---

## Commit Message Style

Use conventional commits:
- `fix: <what was fixed>`
- `chore: update cache-bust version strings`
- `feat: <new feature>`
- `docs: update <document name>`
- `refactor: <what changed>`

---

## What NOT To Do

- Do not run `npm`, `node`, `yarn`, or `pnpm` — there is no package.json
- Do not `git push` without being explicitly asked
- Do not commit `CATCH-admin.html` under any circumstance
- Do not silently ignore errors or warnings
- Do not modify schema data in `tx-workbook-schema-v3.js` without flagging it for review first

---

## Skill Reference

Full step-by-step maintenance workflow:
`catch-tool-maintenance/SKILL.md`

Load it when asked to audit, review, or prepare a commit for this repo.
