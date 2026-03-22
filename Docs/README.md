# CATCH — Contract & Schema Triage Hub

**TX OCA · BIS Internal · Tyler Technologies Courts & Justice**

CATCH is a browser-based diagnostic tool that takes a failed court data submission and returns a plain-English breakdown of every error — what failed, who owns the fix, and what to do next. No schema expertise required. No install. No login. No data leaves your browser.

---

## Quick Start

| Option | How |
|--------|-----|
| **Hosted** | Open the URL provided by BIS TPM. Always current. |
| **Local file** | Download `CATCH.html` and open in Chrome or Edge. Works offline. |

> **Supported browsers:** Chrome and Edge only. Safari and Firefox are not recommended.

---

## What It Does

When a CMS vendor submits court data to a Tyler pipeline and the submission fails, the platform returns a raw JSON error file full of technical schema language. CATCH eliminates the need to interpret that manually.

Paste the failed payload → click **▶ Run Validation** → every error is translated automatically with a fix owner and recommended next step.

CATCH does **not**:
- Submit anything to the pipeline
- Connect to ACB, AEP, or any external system at runtime
- Send your data anywhere — everything runs locally in your browser

---

## Builds

| File | Purpose | Audience |
|------|---------|----------|
| `CATCH.html` | Production build. Schemas embedded. Admin controls removed. | All users |
| `CATCH-admin.html` | BIS-internal master. Schema Manager, Error Library editor, Integrator Inventory upload, Export Production Build. **Never deploy this file publicly.** | BIS TPM only |

---

## Repository Structure

```
/
├── CATCH.html                   # Production build — deploy this
├── CATCH-admin.html             # Admin build — BIS TPM only
└── docs/
    ├── README.md                # This file
    ├── onboarding-guide.md      # Full user walkthrough
    ├── schema-reference.md      # Validation rules, entity types, enums
    ├── error-library.md         # Known error patterns and translations
    ├── integrator-inventory.md  # Source ID registry and county mapping
    ├── aep-discrepancy.md       # AEP vs CATCH validation differences
    └── changelog.md             # Version history
```

---

## Five Tabs

| Tab | What it's for |
|-----|---------------|
| **Validate** | Primary workspace — paste payload, run validation, read results |
| **Schema Reference** | Read-only lookup of all contract rules for the active market |
| **TX Error Log** | Curated log of known TX pipeline failures maintained by BIS TPM |
| **History / Export** | Every validation run saved automatically with CSV/JSON export |
| **About** | Tool overview, coverage notes, limitations, contacts |

---

## Deployment

CATCH deploys to **Azure Static Web Apps** (free tier) from this GitHub repository. Every push to `main` auto-deploys in ~2 minutes. Monthly cost: $0.

The production file (`CATCH.html`) is generated from `CATCH-admin.html` using the **Export Production Build** button in the admin Schema Manager. Schemas and the Error Library are embedded at that point.

---

## Documentation

## Documentation

- [Onboarding Guide](Docs/onboarding-guide.md) — All users · Clients
- [Schema Reference](Docs/schema-reference.md) — BIS TPM · D&I · Technical users
- [Error Library](Docs/error-library.md) — BIS TPM
- [Integrator Inventory](Docs/integrator-inventory.md) — BIS TPM · D&I
- [AEP Discrepancy](Docs/aep-discrepancy.md) — BIS TPM · D&I · Program Leadership
- [Changelog](Docs/changelog.md) — All

> Operations runbook (schema update workflow, GitHub deployment steps, troubleshooting) is maintained as an internal Word document — not stored in this repo.

---

## Contact

**Tool owner / BIS TPM:** Bryce Beltran · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)

Questions, new error patterns not yet translated, or anything about this repo → [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)
