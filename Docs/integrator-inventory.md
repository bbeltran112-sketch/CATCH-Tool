# Integrator Inventory

*Source ID registry, county registration, and how to update CATCH*

**BIS TPM Internal · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)**

---

## What Is the Integrator Inventory?

The Integrator Inventory is a Tyler Technologies reference spreadsheet (`.xlsx`) that maps every Texas court integrator (CMS vendor) to their registered counties, court types, and Alliance Source IDs. CATCH uses two sheets from this file:

| Sheet | What CATCH reads from it |
|-------|--------------------------|
| **Alliance IDs** | Publisher → Source ID mapping per environment (Testing / Staging / Production) |
| **Certified Vendor Mapping** | County → Publisher mapping for the full TX court system |

CATCH uses this data to perform publisher-aware county validation — specifically to enforce that Tyler Tech-Odyssey submissions only include counties within the Source ID's registered scope.

---

## Why County Registration Matters

Tyler Tech-Odyssey's Source ID (`d5aLRYyHcBRAgzDxuBK84D` in Staging) is registered to serve approximately 105 Texas counties. Submissions that include a county outside this registered set will be rejected by the Alliance platform regardless of whether the county name is technically valid.

CATCH enforces this check proactively. When a county fails, the error message reads:

> `"[County]" is a valid Texas county but falls outside the registered county scope for this Source ID (Tyler Tech-Odyssey). Submissions for this county will be rejected by the Alliance until the Source registration is expanded. Submit a ticket to D&I to request county registration expansion.`

This is a **registration issue, not a data error**. Do not ask the vendor to change the county value.

---

## Known Unregistered Counties (Current)

As of March 2026, the following counties appear in Tyler Tech-Odyssey submissions but are not in the registered county scope for Staging:

| County | Entities affected | Status |
|--------|------------------|--------|
| **Llano** | 16 | Unregistered — ticket to D&I required |
| **Colorado** | 2 | Unregistered — ticket to D&I required |

To resolve: submit a ticket to D&I requesting that the Tyler Tech-Odyssey Source ID registration be expanded to include these counties in the Staging environment.

---

## Source ID Reference (Staging)

| Publisher | Staging Source ID |
|-----------|------------------|
| Tyler Tech-Odyssey | `d5aLRYyHcBRAgzDxuBK84D` |
| Engagement Builder | `gWhgJsgonKY8MLxeA73B3m` |

> **Production Source IDs are not yet populated** in the Alliance IDs sheet as of March 2026. Before any production validation, confirm production IDs are entered or AEP validation will produce incorrect results for the same reason it does in Staging today.

---

## AEP vs CATCH — Source ID Discrepancy

AEP's `System_County_Association` schema has a `oneOf/0` branch with `Source: const = gWhgJsgonKY8MLxeA73B3m` — which is the **Engagement Builder** Staging Source ID. When Tyler Tech-Odyssey submits, AEP resolves to the wrong branch and validates against Engagement Builder's rules (2-county enum, different publisher).

CATCH uses the Alliance ID registry to identify the correct Source ID and validates correctly. All AEP errors on `Source`, `county`, and `publisher` for Odyssey submissions are false positives caused by the wrong `oneOf` branch being evaluated.

See [aep-discrepancy.md](aep-discrepancy.md) for the full analysis.

---

## Uploading a New Integrator Inventory (Admin)

When a new Integrator Inventory is available (county registrations change, new Source IDs assigned), update CATCH-admin using the built-in upload feature.

### Steps

1. Open `CATCH-admin.html`
2. Click **⚙** to open Schema Manager
3. Scroll to **Integrator Inventory**
4. Drag and drop the `.xlsx` file onto the drop zone, or click to browse
5. Review the preview — confirm the Odyssey county count and Source IDs look correct
6. Click **Apply Inventory**

CATCH will:
- Parse the **Alliance IDs** sheet for Source ID assignments
- Parse the **Certified Vendor Mapping** sheet for county-to-publisher mappings
- Take a snapshot of the existing `ODYSSEY_COUNTIES` set before overwriting
- Update `ODYSSEY_COUNTIES` in memory immediately

All validation runs in that session will use the new county set. The update is **session-only** — it does not persist across page reloads. To make changes permanent, update `ODYSSEY_COUNTIES` in the source code and rebuild the production file.

### Making a permanent update

To permanently update the registered county set in the production build:

1. Open `CATCH-admin.html` in a text editor
2. Find the `ODYSSEY_COUNTIES` constant (line ~1663)
3. Add or remove counties as needed
4. Save
5. Use **Export Production Build** in Schema Manager to generate the new `CATCH.html`
6. Commit `CATCH.html` to GitHub — Azure auto-deploys within ~2 minutes

### Exporting the active registry

Click **↓ Export Active Registry** in the Integrator Inventory section to download a JSON snapshot of the current `ODYSSEY_COUNTIES` set. Useful for auditing or comparing before/after a registration change.

---

## Integrator Inventory File Format

The upload expects a standard Integrator Inventory `.xlsx` with at minimum these sheets:

**Alliance IDs sheet** — required columns:

| Column | Example |
|--------|---------|
| Environment | `Staging` |
| Publishing System | `Tyler Tech-Odyssey` |
| Publishing System ID | `d5aLRYyHcBRAgzDxuBK84D` |

**Certified Vendor Mapping sheet** — required columns:

| Column | Example |
|--------|---------|
| County | `Clay` |
| Court | `Tyler Tech-Odyssey` |
| Court Type | `District Clerk Office` |

CATCH reads **top-level county-only rows** (no hyphen in County name) to build the registered county set per publisher.

---

## Contact

Registration questions or D&I tickets for county expansion → Submit a ticket to D&I

Tool questions → [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)
