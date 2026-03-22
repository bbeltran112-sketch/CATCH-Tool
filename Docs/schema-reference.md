# CATCH Schema Reference

*Validation engine, entity types, enums, and schema management*

**Version 4.0 · March 2026 · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)**

> **For technical users** — BIS TPM · D&I · Program Leadership

---

## 1. Architecture Overview

CATCH is a single-file HTML application. All validation logic, embedded schemas, and rule sets execute client-side in the browser with no server dependency. The tool is market-agnostic — a schema registry pattern allows any number of markets and pipelines to be added without code changes.

### Two builds

| Build | Purpose | Location |
|-------|---------|----------|
| `CATCH-admin.html` | BIS-internal master. Contains Schema Manager, Error Library editor, Integrator Inventory upload, and Export Production Build. Never deployed publicly. | Local machine + BIS SharePoint |
| `CATCH.html` (production) | Deployed file. Generated from admin via Export Production Build. Schemas and Error Library embedded at deploy time. Admin controls removed. | GitHub repo → Azure Static Web Apps |

### Validation layers

| Layer | Role |
|-------|------|
| **Layer 1 — Schema Validation** | Checks field values, data types, enum membership, required fields, and additional property violations. Rules derived dynamically from D&I-provided schemas or built-in embedded schemas. |
| **Layer 2 — BIS Institutional Layer** | Publisher-aware registration checks, wrong field name traps, error cross-references. Hardcoded. Never overridden by schema uploads. |
| **Layer 3 — Automatic Error Translation** | Each error matched against Error Library. Matching entry delivers plain-English translation, fix owner, and recommended action. Built-in translations run as fallback. |
| **Layer 4 — TX Error Log Auto-logging** | Every run with errors is automatically persisted to the TX Error Log in localStorage. Separate from History tab. |

---

## 2. Payload Ingestion and Normalization

CATCH accepts four formats, all normalized to a flat entity array before validation:

**Format 1 — Full ACB envelope**
```json
{ "Events": [{ "Entities": [{ "EntityType": "...", "EntityData": {...} }] }] }
```

**Format 2 — Simple envelope**
```json
{ "eventType": "...", "entities": [ {...} ] }
```

**Format 3 — Entity array**
```json
[ { "entityType": "...", ... }, ... ]
```

**Format 4 — Single entity**
```json
{ "entityType": "...", "county": "...", ... }
```

During normalization each entity is flattened — `EntityData` fields are merged to the top level. An internal `_eventType` field is injected from the envelope root for context-aware suggestions and excluded from `additionalProperties` checks.

---

## 3. Validation Execution Order

Nine steps run sequentially per entity. Step 1 returns early on invalid entity type. All others run regardless of prior results.

| Step | Description |
|------|-------------|
| **1 — Entity Type Check** | Validates `entityType` against the active market's registered entity type list. Checks `KNOWN_BAD` for recognized misspellings and generates event-type-aware suggestions. Returns immediately on failure. |
| **2 — Required Field Checks** | Validates `recordid`, `county`, and `publisher` are present. Universally required across all entity types. |
| **3 — County Validation (Publisher-Aware)** | Standard entities: validates against full approved county enum. Publishers with restricted Source ID registration: validates against that restricted list only. |
| **4 — Publisher Enum Check** | Validates `publisher` against approved publisher list for the active market. Exact string match. |
| **5 — Active Rules Resolution** | Checks `schemaOverrides[market][entityType]` for uploaded schema. If found: `deriveRulesFromSchema()` then `mergeRules()`. If not: uses `ENTITY_RULES[et]` directly. |
| **6 — Type Violation Checks** | Iterates `activeRules.numOrNull`. Flags any field where value is present, non-null, and `typeof === "string"`. |
| **7 — Enum Validation** | Iterates `activeRules.enums`. Flags values not in allowed array. Notes "(from uploaded schema)" when rule is schema-derived. |
| **8 — Bad Field Name Traps** | Iterates `activeRules.badFields`. Always from built-in `ENTITY_RULES`. Detects known publisher mapping errors. |
| **9 — Additional Properties Check** | Resolves `allowedFields` from uploaded schema properties keys or built-in `ALLOWED_FIELDS` set. Flags undeclared fields not in the reserved internal set. |

---

## 4. Dynamic Schema Derivation

### `deriveRulesFromSchema(schema)`

- **numOrNull detection:** type array includes `"number"` and excludes `"string"` → field added to `numOrNull` list
- **Enum extraction:** property has `enum` array with at least one value → used as allowed values list
- **Required fields:** `schema.required` array converted to `Set`

### `mergeRules(derived, builtin)`

- **numOrNull:** Union — schema derivation can only add checks, never remove them
- **enums:** `Object.assign(builtin.enums, derived.enums)` — derived wins on overlapping fields. Schema is authoritative for allowed values.
- **badFields:** Always from built-in. Wrong field name traps are BIS knowledge not present in schema files.
- **refs:** Always from built-in. OCA/BIS error cross-references are BIS documentation.

> **Additive safety:** A schema upload can only expand validation coverage, never reduce it. Built-in enum rules are preserved for any field the uploaded schema does not define.

---

## 5. Automatic Error Translation

| Path | Description |
|------|-------------|
| **A — Error Library (first)** | `matchLibraryEntry()` iterates library in order. Checks entity type filter, field filter, then match type (`field_value` = exact, `field_name` = exists, `contains` = substring). First match wins. Built-in bypassed. |
| **B — Built-in translation (fallback)** | Covers structural patterns stable across markets: type violations, enum errors, `additionalProperties`, county registration gaps, fake county, wrong field names, publisher errors. |
| **C — No translation (signal)** | Raw error shown. Signal to BIS TPM to add a new Error Library entry. |

---

## 6. County Validation

### v3.0.0 entity types

County must be a plain Texas county name (e.g. `"Clay"`, `"Eastland"`). No subdivisions.

For **Tyler Tech-Odyssey** specifically, county is additionally checked against the Source ID's registered county list (~105 counties in Staging). Counties that are valid Texas counties but outside the registered set produce this error:

> `"Llano" is a valid Texas county but falls outside the registered county scope for this Source ID (Tyler Tech-Odyssey). Submit a ticket to D&I to request county registration expansion.`

This is a D&I/registration issue, not a data error. Do not ask the vendor to change the county value.

### v0.1 entity types

County must be in `County-Subdivision` format (e.g. `"Grayson-Sherman"`). Full list maintained in `V01_COUNTIES` in source.

### AEP discrepancy

AEP's `System_County_Association` schema currently uses a `oneOf` branch keyed to the Engagement Builder Source ID, not Tyler Tech-Odyssey. This causes AEP to flag every Odyssey county value as invalid. These are false positives — CATCH does not replicate them. See [aep-discrepancy.md](aep-discrepancy.md) for the full analysis.

---

## 7. Schema Manager (Admin Only)

The Schema Manager is accessible in `CATCH-admin.html` via the **⚙** button.

### Upload Schemas

Drop one or more JSON schema files onto the drop zone or click to browse. Select the market (TX, IL, or custom). Click **Apply Schemas**. A rollback snapshot is taken automatically before applying.

Uploaded schemas are stored in localStorage under `bis_schema_overrides_{market}`. They take precedence over built-in enum rules for the fields they define. Built-in `badFields` and `refs` are always preserved.

### Rollback & Reset

- **↩ Rollback** — restores the previous schema set for the selected market from the auto-snapshot taken before the last upload.
- **✕ Reset to Built-in** — removes all uploaded schemas for the market and returns to the embedded defaults.

### Active Schema Inventory

Lists all schemas currently loaded per market. Green indicates uploaded; plain text indicates built-in.

---

## 8. Integrator Inventory (Admin Only)

The Integrator Inventory section in the Schema Manager allows uploading the Integrator Inventory `.xlsx` file to update Source ID and county registration data live.

On upload, CATCH reads two sheets:
- **Alliance IDs** — maps each publisher to its Source ID per environment (Testing / Staging / Production)
- **Certified Vendor Mapping** — maps county to publisher for the full TX court inventory

On apply, `ODYSSEY_COUNTIES` is updated in memory immediately. All subsequent validation runs in that session use the new county set. See [integrator-inventory.md](integrator-inventory.md) for the full registry management process.

---

## 9. Security Architecture

Six security features operate at the storage, display, or download layers. None affect validation behavior.

| Feature | Layer | Implementation |
|---------|-------|----------------|
| **XSS / `escHtml()`** | Display | Encodes `&`, `"`, `<`, `>` at all innerHTML call sites. Fires at DOM render time after validation completes. |
| **PII Scrubber — `scrubRunPII()`** | Storage | Intercepts every history entry before localStorage/sessionStorage write. Strips SSN patterns (`\d{3}-\d{2}-\d{4}`), date strings, and name-bearing field values. Never touches live validation payload. |
| **Session-Only Toggle** | Storage | Boolean preference in localStorage routes all history/error log writes to sessionStorage instead. sessionStorage cleared on tab close. Toggle preference itself persists. |
| **Inactivity Auto-Clear** | UI | `mousemove`/`keydown`/`scroll` listeners reset 30-min timer. Warning toast at 25 min. Clears textarea and results panel at 30 min. History unaffected. |
| **Export Warning Modal** | Download | All export functions are async and `await confirmExport()`. Modal names specific file. Cancel aborts download entirely. |
| **History TTL — `pruneExpiredRuns()`** | Storage | Called on every `loadHistory()`. Filters runs older than 7 days. Entries with missing/unparseable timestamps kept to avoid data loss. |

### localStorage key reference

| Key | Contents | Sensitivity |
|-----|----------|-------------|
| `tx_oca_di_val_history_v1` | Up to 200 full validation runs including pasted payload JSON | **HIGH** — real court record data if live payloads used |
| `catch_tx_error_log_v1` | Auto-logged error records from validation runs | MEDIUM |
| `catch_tx_error_log_cap_v1` | User-configured log cap (integer, default 500) | LOW |
| `catch_error_library_v1` | BIS error definitions (BIS-001–006+) | LOW |
| `bis_schema_overrides_{market}` | Uploaded D&I schemas | LOW |
| `bis_schema_backup_{market}` | Schema rollback snapshots | LOW |
| `catch_session_only_pref` | Session-Only toggle preference (boolean) | LOW |

---

## 10. TX Error Log — Auto-Logging

Two entry types:
- **Manually pinned BIS entries** (OCA-006 through OCA-011, `source: "pinned"`)
- **Auto-logged entries** from validation runs (`source: "auto"`)

- **Storage key:** `catch_tx_error_log_v1` (localStorage)
- **Cap:** `catch_tx_error_log_cap_v1` — user-configured, default 500, range 100–10,000
- **Overflow:** entries auto-exported to dated JSON file before trimming — no data lost
- **ID format:** `AUTO-{timestamp}-{random4}` — unique per entry
- **Granularity:** one log entry per failing entity per run — `cause` field concatenates all errors for that entity

---

## 11. Operational Model

| Who | Role |
|-----|------|
| **BIS TPM** | Owns and operates CATCH. Manages schema updates, Error Library, and all deployments. Single point of contact for the tool. |
| **D&I / Analytics Team** | Maintains contract schemas and pipeline platform. Provides schema updates to BIS TPM. Does not operate CATCH directly. |
| **Support Staff** | Primary users. Paste failed payloads, read translated output, escalate correctly. |
| **CMS Vendors / Publishers** | Receive fix guidance derived from CATCH output. Do not interact with the tool directly. |
| **State / Governing Body** | Owns data requirements. Approves contract schema content. Involved only when fix owner = Governing Body. |

---

## 12. Infrastructure

- Hosted on **Azure Static Web Apps** — free tier, no expiry
- Source controlled in a private GitHub repository
- Auto-deploys on every push — ~2 minute deployment cycle
- Monthly cost: **$0**. File size ~500KB against a 1GB free tier limit.
- No backend infrastructure, no database, no server to maintain

---

## 13. Contact

**Tool owner / BIS TPM:** Bryce Beltran · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)

D&I technical issues → Submit a ticket to D&I
