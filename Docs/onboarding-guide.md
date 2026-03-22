# CATCH Onboarding Guide

*Everything you need to start using CATCH from scratch*

**Version 1.0 · March 2026 · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)**

> **For all users** — new support staff · experienced support staff · program leadership · clients

---

## Which Document Should I Read?

| If you are... | Read this | What you'll get |
|---------------|-----------|-----------------|
| New to CATCH or learning the tool | ✅ **This document** | Full walkthrough, every feature explained from scratch |
| Technical user, BIS TPM, or D&I | [Schema Reference](schema-reference.md) | Validation engine, security architecture, deployment model |
| BIS TPM managing operations | Operations Runbook *(internal Word doc)* | Schema updates, GitHub deployment, file locations, troubleshooting |

You are in the right place. This guide assumes no prior knowledge of CATCH, schemas, or pipeline validation. Read it top to bottom before using the tool for the first time.

---

## 1. What Is CATCH?

CATCH stands for **Contract & Schema Triage Hub**. It is a tool built by Tyler Technologies Business Integration Services (BIS) that does one thing: takes a failed court data submission and tells you exactly what went wrong, in plain English, automatically.

### The problem it solves

When a CMS vendor submits court data to a Tyler pipeline and the submission fails, the platform returns a raw JSON error file full of technical schema language that is hard to act on without deep knowledge of the contract rules. Figuring out what it means, who owns the fix, and what to tell the vendor used to require a subject matter expert.

CATCH eliminates that. You paste the failed payload in, click Run, and every error comes back translated into plain English with the fix owner and recommended next step — automatically, on every run.

### What CATCH is not

- It does not submit anything to the pipeline
- It does not connect to ACB, AEP, or any external system at runtime
- It does not send your data anywhere — everything runs locally in your browser
- It is a diagnostic tool — it tells you what is wrong, it does not fix it

> **No install, no login, no internet required after opening.** CATCH is a single HTML file that runs entirely in your browser.

---

## 2. How to Access CATCH

BIS provides CATCH in two ways. Either works identically.

**Option A — Hosted URL**

Visit the link BIS provides. Open it in Chrome or Edge. The tool loads immediately and you always get the latest version automatically. No action required when BIS pushes updates.

**Option B — Downloaded file**

Download `CATCH.html` and open it directly in Chrome or Edge. Works completely offline. To get a newer version, download again when BIS announces an update.

> **Chrome and Edge are the supported browsers.** Safari and Firefox are not recommended — minor rendering differences may occur.

---

## 3. The Layout — Five Tabs

| Tab | What it's for | How often you use it |
|-----|---------------|----------------------|
| **Validate** | Primary workspace. Paste a failed payload here and run validation. | Every time — this is the main tab |
| **Schema Reference** | Read-only lookup of all contract schema rules for the active market. | Occasionally — for reference lookups |
| **TX Error Log** | Curated log of known TX pipeline failures maintained by BIS TPM. | When cross-referencing a known issue |
| **History / Export** | Every validation run you have done, saved automatically. | End of session, when building tickets |
| **About** | Tool overview, coverage notes, limitations, and contacts. | Rarely — orientation only |

At the top left there is a market/state selector. Currently **TX OCA Community** is the active market. This controls which contract schemas and rules the tool validates against. Leave this as-is unless instructed by BIS TPM.

---

## 4. Running a Validation — Step by Step

### What you need before you start

- The original payload JSON that was submitted to the pipeline
- The **EnvelopeId** — log this first. D&I needs it to locate the transaction if escalation is required.

### The steps

1. Go to the **Validate** tab.
2. Paste the full payload JSON into the left pane.
3. If the payload is a wall of unreadable text with no spacing, click **⇄ Format**. It auto-indents the JSON so it is readable. It does not change any data — just the formatting.
4. Type the EnvelopeId into the envelope field above the pane if you have it. This is optional but recommended — it gets saved with the run in History.
5. Click **▶ Run Validation**. Results appear immediately.

> You do not need to understand JSON or schemas to run a validation. You are copying and pasting a file the vendor sent — the tool does the rest.

---

## 5. Reading the Results

### The summary bar

As soon as a run completes, a summary bar appears at the top of the results panel:

```
eventType: di-texas-oca-new-record-event · entities: 51 · ✗ 18 errors · 33 valid
```

This bar is interactive. Clicking the counts filters the results panel:

| Click this | What happens |
|------------|--------------|
| **✗ 18 errors** | Hides all passing entities — shows only the failing ones. On a large payload this is the first thing to click. |
| **33 valid** | Hides all failing entities — shows only the ones that passed. |
| **✕ clear filter** *(appears when active)* | Resets back to showing everything. |

The active filter gets a subtle highlight so you can always see which view is on. Running a new validation resets the filter automatically.

### Entity cards

Each entity in the payload gets its own result card. The card header shows:

- ✓ **VALID** or ✗ **INVALID** — pass or fail status
- Entity number (Entity 1, Entity 2, etc.)
- entityType, entityId, recordid, county
- Error count badge on failing cards (e.g. "3 errors")

### Each error shows three things

| What you see | What it means |
|--------------|---------------|
| **Field name** | Which field in the payload triggered this error (e.g. `county`, `plea_type`, `entityType`) |
| **Technical message** | The raw error from the validator — what the schema check found |
| **Plain-English translation** | What it actually means and what to do. Comes from the Error Library automatically. You never look anything up manually. |

> Every error is translated automatically on every run. The translation tells you what failed, who owns the fix, and what the recommended next step is.

---

## 6. Fix Owners — Who Does What

Every translated error includes a fix owner:

| Fix Owner | What it means | What you do |
|-----------|---------------|-------------|
| **Publisher** | The CMS vendor needs to fix something in their data mapping or submission code. | Send the vendor the error details. CATCH's translation tells them what to fix. |
| **D&I** | A pipeline registration or platform issue that only the D&I team can resolve. | Escalate to BIS TPM with the EnvelopeId and full CATCH output. |
| **BIS TPM** | Needs BIS involvement — usually governing body approval is required before D&I can act. | Escalate to BIS TPM. Do not action this yourself. |
| **Governing Body** | A scope decision that requires the state representative to approve. | Escalate to BIS TPM. This is the longest path — approval required before anything else can happen. |

---

## 7. After You Get Results

### Copy Results

The **⎘ Copy Results** button copies the full translated output as clean plain text to your clipboard. Use this to paste into a Jira ticket, email, or Teams message. It formats as one entity per block with errors listed beneath — ready to send without any editing.

### The run is saved automatically

The moment validation completes, the run is saved to your History tab. You do not need to do anything. Every run you have ever done accumulates there — timestamp, EnvelopeId, entity count, error count, and full error details.

---

## 8. History & Export Tab

Every validation run you have ever done lives here, newest first. This is where you go at the end of a session, when building a ticket, or when a run comes up again weeks later.

### What you can do with a single run

| Action | Use it when... |
|--------|----------------|
| **Export CSV** | Building a ticket or sending results to a vendor. One row per error, named with the EnvelopeId. Most useful format for escalations. |
| **Export JSON** | You need the full structured output for technical handoffs or BIS records. |
| **Expand inline** | You want to review the error list without exporting. |

### Bulk actions

- **Save All** — exports your entire history as a JSON file. Do this before clearing your browser cache. It is the only backup of your run history.
- **Import** — loads a history JSON file. Safe to run multiple times — duplicates are removed automatically.

> **Runs older than 7 days are automatically removed from history on each load.** If you need to keep a run longer, export it before it expires.

### Export warning

Before every download a confirmation modal appears naming the specific file and reminding you to save it to an approved, secure location. Click **Confirm Export** to proceed or **Cancel** to abort.

---

## 9. Security Features

Six security features run quietly in the background. The one worth knowing actively is **Session-Only mode**.

| Feature | What it does | Do you need to do anything? |
|---------|-------------|------------------------------|
| **PII Scrubber** | Before any run is saved to history, known personal fields (party names, SSNs, dates) are automatically stripped from the stored copy. What you see on screen is unaffected. | No — automatic |
| **Session-Only toggle** | Orange checkbox in the header bar. When on, nothing is written to persistent browser storage. Everything clears when the tab closes. | **Yes** — turn it on for sensitive runs or on shared workstations |
| **Inactivity auto-clear** | If you leave CATCH open and idle, a warning appears at 25 minutes. The live workspace clears at 30 minutes. Saved history is not affected. | No — automatic |
| **Export warning modal** | Confirmation required before every download. Reminds you to save to an approved location. | **Yes** — read and confirm before exporting |
| **History TTL** | Runs older than 7 days are silently removed on each load. | No — automatic. Export anything you need to keep. |
| **XSS protection** | All payload content is sanitized before display. Prevents malicious payloads from running code in your browser. | No — automatic |

---

## 10. Common Scenarios

### Scenario A — Vendor reports a failed submission

1. Get the EnvelopeId and full payload JSON from the vendor.
2. Paste into the Validate tab, click **▶ Run Validation**.
3. Click **✗ errors** in the summary bar to filter to failing entities only.
4. Read the plain-English translations — identify the fix owner for each error.
5. Click **⎘ Copy Results** and paste into your ticket.
6. If fix owner is **Publisher** — send the vendor the translated error details.
7. If fix owner is **D&I** or **BIS TPM** — escalate with EnvelopeId and CATCH output.

### Scenario B — You see an error with no translation

If an error shows only the raw technical message with no plain-English translation below it, that is a new error pattern not yet in the Error Library. Copy the full CATCH output and send it to BIS TPM at [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com). BIS TPM will diagnose it and add it to the library so future matches are translated automatically.

### Scenario C — ACB says 1 error but CATCH shows 15

This is expected and intentional. ACB stops validating after the first failing entity in a batch. CATCH validates every entity independently and surfaces all violations in one pass. The 15 errors all exist — CATCH is showing you the complete picture so the vendor can fix everything in one resubmission instead of discovering errors one at a time.

### Scenario D — You see "county not in publisher's registered set"

This is not a data error. The county name is correct — but the publisher's Source ID is not registered to submit data for that county. Do not tell the vendor to change their county value. Escalate to BIS TPM with the EnvelopeId and the list of counties involved. This requires D&I action and likely governing body approval.

---

## 11. What to Ignore

Two errors appear at the bottom of almost every failed submission. You can safely ignore them:

| Error text | Why it appears | What to do |
|------------|----------------|------------|
| `'Source const' error` | Fires automatically whenever any entity fails — it is structural noise from how the pipeline schema is built internally. | Ignore. Fix the real errors above it and this disappears. |
| `'must match a schema in anyOf'` | Same cause as above — validator noise, not a real actionable error. | Ignore. Not a real error. |

---

## 12. Contacts & Support

| Role | Contact |
|------|---------|
| CATCH tool owner · BIS TPM | Bryce Beltran · [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com) |
| D&I technical issues | Submit a ticket to D&I |
| TX pipeline technical issues | [vendorsupport@txcourts.gov](mailto:vendorsupport@txcourts.gov) |

> Questions about CATCH, new error patterns not yet translated, or anything in this guide → [BIS.TPM@tylertech.com](mailto:BIS.TPM@tylertech.com)
