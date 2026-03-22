# CATCH Error Library

*Known error patterns, translations, and management*

**BIS TPM Internal · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)**

---

## What Is the Error Library?

The Error Library is a codified catalog of known validation error patterns. When CATCH runs validation, every error is matched against the library first. A matching entry delivers a plain-English translation, fix owner, and recommended action automatically — no manual lookup required.

The library is stored in browser localStorage under `catch_error_library_v1` and is editable in `CATCH-admin.html` via the **⚙ Schema Manager → Error Library** section.

---

## How Matching Works

`matchLibraryEntry()` iterates the library in order and returns on the **first match**. Three match types:

| Match Type | How it matches |
|------------|----------------|
| `field_value` | Exact match on both field name and field value |
| `field_name` | Field name exists in the entity, regardless of value |
| `contains` | Field value contains the match string (case-insensitive substring) |

Each entry also filters on:
- **Entity Type** — if set to anything other than `All`, only matches entities of that type
- **Field** — the specific field name to check

> **Entry order matters.** More specific rules (narrow entity type + `field_value`) should appear before general ones (`All` entity type or `field_name` match). The first match wins and no further entries are checked.

If no library entry matches, CATCH falls back to built-in translations. If those also don't cover the pattern, the raw error is shown — which is a signal to BIS TPM to add a new entry.

---

## Built-In Entries (BIS-001 through BIS-006)

These six entries are pre-loaded on first use and cover the most common structural errors across all TX OCA entity types.

| ID | Entity Type | Field | Match Type | Translation Summary |
|----|------------|-------|------------|---------------------|
| BIS-001 | All | `entityType` | `field_name` | Unknown entity type — likely a misspelling. See schema reference for valid types. |
| BIS-002 | All | `county` | `field_name` | County missing or invalid for this publisher's registration scope. |
| BIS-003 | All | `publisher` | `field_name` | Publisher not in approved enum. Check for exact string match. |
| BIS-004 | `di-texas-oca-court-charges` | `plea_type` | `field_value` | Odyssey is submitting plain-English plea values (e.g. "Guilty") but the schema requires letter-code format (e.g. "G - Guilty"). Fix owner: Odyssey CMS data mapping. |
| BIS-005 | `di-texas-oca-court-charges` | `party_race` | `contains` | "Not Available" is not valid — the correct value is "Not Available (Blank)" (exact match required). Fix owner: Odyssey CMS data mapping. |
| BIS-006 | All | `case_status_event` | `field_value` | The case status event value does not match the approved enum. Check the OCA data dictionary for valid values. |

---

## Built-In Static Translations (Fallback)

In addition to the editable library, CATCH has hardcoded translations for structural patterns that are stable across all markets. These fire when no library entry matches.

| Pattern | Translation |
|---------|-------------|
| `additionalProperties` on `court-case-status` | Odyssey is likely submitting appointment-entity data under the wrong entity type. The EntityType should be `di-texas-oca-court-appointments`. Fix owner: Odyssey CMS mapping. |
| `additionalProperties` (general) | Publisher is sending extra fields not defined in the contract schema. Remove this field from the payload. Fix owner: submitting publisher. |
| `Must be number\|null` | Field must be a number (e.g. `35`), not a quoted string (e.g. `"35"`). The CMS is serializing this value incorrectly. Fix owner: Odyssey CMS data mapping. |
| `Wrong field name` | The field was submitted under the wrong name. Rename to the correct field name in the CMS mapping. Fix owner: Odyssey CMS team. |
| `Invalid value` on `plea_type` | Odyssey is submitting plain-English plea values. Schema requires letter-code format. Fix owner: Odyssey CMS data mapping. |
| `Invalid value` on `party_race` | "Not Available" is not valid — use "Not Available (Blank)". Fix owner: Odyssey CMS data mapping. |
| `Invalid value` on `case_status_event` | Value does not match approved enum. Check OCA data dictionary. Fix owner: submitting publisher. |
| `registered for ~105 counties` | Valid Texas county but outside registered county scope for this Source ID. Submit a ticket to D&I to request county registration expansion. |

---

## Managing Library Entries (Admin)

Open `CATCH-admin.html` → click **⚙** → scroll to **Error Library**.

### Adding a new entry

1. Click **+ New Entry**
2. Fill in: ID, Entity Type, Field, Match Type, Match Value, Translation, Fix Owner, Recommended Action
3. Click **Save**

### Editing an existing entry

Click the entry row to expand it, make changes, click **Save**.

### Import / Export

- **↓ Export** — downloads the full library as a JSON file (`CATCH_Error_Library_YYYY-MM-DD.json`)
- **↑ Import** — merges a JSON file into the current library. Duplicate IDs are skipped automatically.

### Entry fields

| Field | Description |
|-------|-------------|
| **Entry ID** | Auto-generated (BIS-001, BIS-002…). Editable. Used for deduplication on import. |
| **Entity Type** | Which entity type this rule applies to. Use `All` to match any entity type. |
| **Field** | Which field name triggers this rule. |
| **Match Type** | `field_value` (exact), `field_name` (field exists), `contains` (substring) |
| **Translation** | Plain-English explanation shown automatically when matched. |
| **Recommended Action** | What to do — shown alongside translation. |
| **Fix Owner** | `Publisher` / `D&I` / `BIS TPM` / `Governing Body` |
| **OCA Ref** | Optional OCA issue reference (e.g. `OCA-010`). Displayed as an orange badge. |

---

## When You See an Untranslated Error

If an error in CATCH output shows only the raw technical message with no plain-English translation, that is a **new pattern not yet in the library**. Steps:

1. Copy the full CATCH output (use **⎘ Copy Results**)
2. Note the field name, error message, and entity type
3. Send to [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)
4. BIS TPM will diagnose, add the entry to the library, and rebuild production

Future occurrences of the same pattern will be translated automatically.

---

## Known Errors to Ignore

Two errors appear at the bottom of almost every failed submission. They are validator noise — not real errors.

| Error text | Why it appears | Action |
|------------|----------------|--------|
| `'Source const' error` | Fires automatically whenever any entity fails — structural noise from the pipeline schema's `oneOf` evaluation. | **Ignore.** Fix the real errors above it. |
| `'must match a schema in anyOf'` | Same cause — validator cascade noise. | **Ignore.** Not actionable. |

See [aep-discrepancy.md](aep-discrepancy.md) for the full technical explanation of why these errors appear.

---

## Contact

Questions or new patterns to add → [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)
