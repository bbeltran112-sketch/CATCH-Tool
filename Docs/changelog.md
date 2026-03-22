# Changelog

All notable changes to CATCH are documented here.

Format: `## [Version] — Month YYYY` with sections for Added, Changed, Fixed, and Removed.

---

## [4.0] — March 2026

### Added
- **Integrator Inventory upload** (`CATCH-admin.html`) — drag-and-drop `.xlsx` upload in Schema Manager. Parses Alliance IDs sheet (Source ID mapping) and Certified Vendor Mapping sheet (county registration) from the Integrator Inventory file. Updates `ODYSSEY_COUNTIES` in memory for the current session. Preview before applying. Export active registry to JSON. Status badges show current county count and Source IDs.
- **AEP Validator Discrepancy Advisory** in Schema Reference panel — explains the Engagement Builder / Tyler Tech-Odyssey `oneOf` branch misconfiguration in AEP, why CATCH results differ, and resolution path.
- **`aep-discrepancy.md`** — full documentation of the AEP vs CATCH validation discrepancy with root cause analysis, false positive breakdown, and stakeholder messaging guidance.
- Markdown documentation set (`docs/`) — README, onboarding guide, schema reference, error library, integrator inventory, changelog. All docs converted from Word to GitHub-native markdown.

### Changed
- County error messages — removed individual OCA contact names. All escalation guidance now reads "Submit a ticket to D&I".
- Known Limitations — Source branch validation note updated to explain the AEP Engagement Builder/Odyssey Source ID mismatch. No longer marked as pending confirmation.
- Contact section — removed individual OCA names. Tool owner contact (BIS TPM) retained.
- "Pending Deprecation" section title — removed individual names.
- `ODYSSEY_COUNTIES` inline note updated to reference D&I ticket process for registration expansion.

### Fixed
- County error translation message no longer references external individuals by name.

---

## [3.0] — March 2026

### Added
- Six security features: XSS/`escHtml()`, PII Scrubber (`scrubRunPII()`), Session-Only toggle, Inactivity auto-clear (25 min warning / 30 min clear), Export warning modal (`confirmExport()`), History TTL (`pruneExpiredRuns()`, 7-day expiry).
- TX Error Log auto-logging — every run with errors persisted to `catch_tx_error_log_v1`. Configurable cap (100–10,000, default 500). Overflow auto-exported before trimming.
- Summary bar filter — click error/valid counts to filter results panel. Active filter highlighted. Clears on new run.
- Filter clear button (`✕`) appears when a filter is active.
- Error Library (`catch_error_library_v1`) — codified error patterns with plain-English translations. Six default entries (BIS-001 through BIS-006). Add/edit/delete/import/export in admin UI. Entry order controls match priority.
- Schema Manager rollback — auto-snapshot before every schema upload. Rollback button restores previous set per market.
- Dynamic schema derivation (`deriveRulesFromSchema`) and rule merging (`mergeRules`) — uploaded schemas win on enum values; built-in `badFields` and `refs` always preserved.
- EnvelopeId override field in History tab.
- `KNOWN_BAD` entity type registry — recognized misspellings generate event-type-aware correction suggestions.

### Changed
- Validation engine refactored to nine sequential steps with publisher-aware county check (Step 3).
- Error translation moved to three-path resolution: Error Library → built-in static → raw (untranslated signal).
- History export includes full error details per run.

---

## [2.0] — February 2026

### Added
- Schema Manager (`⚙`) — upload D&I schema JSON files per market. Applied schemas stored in `bis_schema_overrides_{market}`. Reset to built-in option.
- Multi-format payload ingestion — full ACB envelope, simple envelope, entity array, single entity. All normalized to flat entity array before validation.
- v3.0.0 and v0.1 entity type support with separate county validation paths.
- Publisher-aware county validation — `ODYSSEY_COUNTIES` set enforces ~105-county registered scope for Tyler Tech-Odyssey.
- Additional properties check (Step 9) — flags fields not in contract schema.
- Bad field name traps — detects known publisher mapping errors (e.g. `filing_statute_citation` → `statute_citation`).
- IL market slot in market selector (schema not yet active).

### Changed
- History tab now auto-saves every run without requiring explicit save action.
- Results panel supports inline expansion without export.

---

## [1.0] — January 2026

### Added
- Initial release. Single-file HTML application.
- Validate tab — paste JSON payload, run validation, read results.
- Schema Reference tab — read-only rule lookup.
- History / Export tab — per-run CSV and JSON export, bulk Save All / Import.
- About tab — tool overview and contacts.
- TX OCA as initial active market with embedded v3.0.0 schemas.
- Five-tab layout with market selector.
- Basic enum validation, required field checks, entity type validation.
- Copy Results button — full translated output to clipboard.
- ⇄ Format button — auto-indent JSON in input pane.

---

*Questions about a specific release → [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)*
