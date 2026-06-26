# STIG Deviation AI Justification Workflow

> Planning document for adding an AI-assisted justification and mitigating-controls workflow to the STIG Deviation merge project.
>
> Goal: keep the existing workbook merge process deterministic in Python while using Gemini only to draft reviewable compliance language.

---

## Current Context

The existing `STIG Deviation Merge Engineer` workflow creates an output workbook with a main sheet named:

```text
Master Tracker Evaluation
```

That sheet has one row per IP address / asset.

The key columns for the next phase are:

```text
Benchmark Exceptions List
Justifications for Exemptions
Mitigating Controls
Compensating Controls
```

The next goal is to create a controlled workflow where new entries in `Benchmark Exceptions List` can be used to draft addendum language for:

```text
Justifications for Exemptions
Mitigating Controls
```

The AI should help draft reviewable language, but Python should remain responsible for detection, tracking, import/export, and workbook updates.

---

## Core Design Principle

Do **not** let AI directly overwrite final workbook columns.

Use this safer workflow instead:

```text
Python detects new exceptions
        ↓
Python creates review packets
        ↓
Gemini drafts justification / mitigation language
        ↓
Python imports drafts into review columns
        ↓
Human reviewer approves or edits
        ↓
Python appends approved text to final columns
```

The AI output should be treated as a draft recommendation, not as an approved final compliance decision.

---

## Recommended Git Branch

Before making changes:

```bash
git status
git add .
git commit -m "Working baseline before AI justification workflow"
git checkout -b feature/ai-justification-ledger
```

---

# Workflow Phases

## Phase 1 — Modify the Original Merge Script

The existing merge script should continue creating the workbook, but it should also create a new helper sheet:

```text
Exception Ledger
```

### Exception Ledger Purpose

The `Exception Ledger` is the tracking table for every unique finding / exception / asset combination.

It should answer:

- Which findings exist?
- Which findings are new?
- Which findings have already been processed?
- Which findings need AI draft language?
- Which findings already have imported AI output?
- Which findings have been reviewed and appended?

### Exception Ledger Grain

```text
1 row per unique exception / finding / asset combination
```

### Recommended Exception Ledger Columns

```text
Exception_ID
IP Address
Host Name
Source Sheet
Plugin ID
STIG
FINDING
CAT
Severity
Result
Short Desc
Plugin Name
Pasteable
Compliance Reference
First Seen Date
Last Seen Date
Exception Status
Already In Benchmark Exceptions List?
Needs AI Draft?
AI Packet File
AI Response File
AI Draft Imported?
Reviewer Status
Approved to Append?
Appended to Master?
Append Date
Notes
```

### Exception_ID Recommendation

`Exception_ID` should be stable and unique.

Recommended structure:

```text
IP Address + STIG + FINDING + Plugin ID + hash(Pasteable)
```

Example conceptual format:

```text
10.10.5.25|V-123456|SV-123456r1_rule|98765|a1b2c3d4
```

This allows the workflow to detect whether an exception has already been processed.

---

## Phase 2 — Add AI Review Columns to Master Tracker Evaluation

Do not immediately append AI-generated text into the final columns.

Add helper/review columns to `Master Tracker Evaluation`:

```text
New Exceptions Pending AI Draft
AI Draft Justification Addendum
AI Draft Mitigating Controls Addendum
AI Source References Used
AI Assumptions / Gaps
AI Confidence
Reviewer Status
Reviewer Notes
Ready to Append?
Append Completed?
```

### Final Columns to Preserve

The final authoritative columns remain:

```text
Benchmark Exceptions List
Justifications for Exemptions
Mitigating Controls
Compensating Controls
```

These should only be updated after human review.

---

## Phase 3 — Decide Packet Grain

The `Exception Ledger` should stay at one row per exception.

However, AI packets should usually be grouped by asset.

### Recommended Packet Grain

```text
1 packet per IP address containing all unprocessed exceptions for that IP
```

### Why Group by IP Address?

The final workbook row is one row per IP address.

If one asset has many new findings, it is usually better for Gemini to draft one coherent asset-level addendum instead of many disconnected paragraphs.

The packet generator should group rows where:

```text
Needs AI Draft? = TRUE
```

by:

```text
IP Address
```

---

## Phase 4 — Create Packet Generator Script

Create a new script:

```text
generate_ai_packets.py
```

### Script Purpose

The packet generator should:

1. Read the output workbook.
2. Read `Master Tracker Evaluation`.
3. Read `Exception Ledger`.
4. Find exceptions where `Needs AI Draft? = TRUE`.
5. Group those exceptions by `IP Address`.
6. Create one packet file per IP address.
7. Update the `AI Packet File` column in the ledger.

### Recommended Output Folder

```text
ai_packets/
```

### Example Packet Files

```text
ai_packets/10.10.5.25_packet.md
ai_packets/10.10.5.26_packet.md
ai_packets/10.10.5.27_packet.md
```

### Recommended Packet Format

Use Markdown for manual Gemini use, with structured JSON inside the file.

The packet should include:

```text
Instructions to Gemini
+
structured JSON packet
+
required JSON response format
```

This keeps manual copy/paste easy while preserving structured data.

---

## Phase 5 — Create the Second Gemini Gem

Create a second Gem named something like:

```text
STIG Deviation Justification Engineer
```

### Gem Purpose

The Gem should:

- Read one asset packet.
- Review the new Benchmark Exceptions List entries.
- Use only the provided exception data and system documentation excerpts.
- Draft addendum language for `Justifications for Exemptions`.
- Draft addendum language for `Mitigating Controls`.
- Identify source references used.
- Identify assumptions and missing information.
- Return structured output that Python can import.

### Gem Boundaries

The Gem should **not**:

- Make final risk decisions.
- Claim final approval.
- Invent system details.
- Invent controls not supported by the provided documentation.
- Overwrite existing text.
- Draft language for old exceptions unless explicitly requested.

### Recommended Gemini Output Format

Ask Gemini to return JSON:

```json
{
  "ip_address": "",
  "host_name": "",
  "exceptions_reviewed": [],
  "draft_justification_addendum": "",
  "draft_mitigating_controls_addendum": "",
  "source_references_used": [],
  "assumptions_or_gaps": [],
  "confidence": "High | Medium | Low",
  "review_recommended": true
}
```

---

## Phase 6 — Manually Run Packets Through Gemini

Start manually before attempting automation.

### Manual Test Set

Begin with 3–5 assets:

```text
1 simple asset
1 asset with many findings
1 asset with messy existing justification text
1 asset with insufficient documentation
1 public-facing asset, if applicable
```

### Manual Process

1. Open a packet from `ai_packets/`.
2. Paste it into the `STIG Deviation Justification Engineer` Gem.
3. Review Gemini's output.
4. Save the response as a JSON file in:

```text
ai_responses/
```

### Example Response Files

```text
ai_responses/10.10.5.25_response.json
ai_responses/10.10.5.26_response.json
ai_responses/10.10.5.27_response.json
```

---

## Phase 7 — Create Response Importer Script

Create a new script:

```text
import_ai_responses.py
```

### Script Purpose

The response importer should:

1. Read files from `ai_responses/`.
2. Validate each response.
3. Match each response to the correct `IP Address`.
4. Optionally match reviewed exceptions to `Exception_ID` values.
5. Write draft output into review columns.
6. Update `Exception Ledger` status fields.
7. Avoid changing final authoritative columns.

### Master Tracker Evaluation Columns to Update

```text
AI Draft Justification Addendum
AI Draft Mitigating Controls Addendum
AI Source References Used
AI Assumptions / Gaps
AI Confidence
Reviewer Status
```

Recommended value:

```text
Reviewer Status = Pending Review
```

### Exception Ledger Columns to Update

```text
AI Response File
AI Draft Imported?
Reviewer Status
```

Recommended values:

```text
AI Draft Imported? = TRUE
Reviewer Status = Pending Review
```

---

## Phase 8 — Human Review

The reviewer should inspect the imported AI draft text.

The reviewer may:

- Accept the draft.
- Edit the draft.
- Reject the draft.
- Request more documentation.
- Mark the row ready for append.

### Review Columns

```text
Reviewer Status
Reviewer Notes
Ready to Append?
```

Only set this when the draft is approved:

```text
Ready to Append? = TRUE
```

---

## Phase 9 — Append Approved Drafts to Final Columns

Create a final script:

```text
append_approved_ai_drafts.py
```

### Script Purpose

The append script should:

1. Find rows where `Ready to Append? = TRUE`.
2. Confirm `Append Completed?` is not already true.
3. Append approved justification text to `Justifications for Exemptions`.
4. Append approved mitigating control text to `Mitigating Controls`.
5. Mark `Append Completed? = TRUE`.
6. Update the `Exception Ledger`.
7. Preserve existing text.

### Recommended Append Header

Use a clear header when appending:

```text
[Deviation Addendum - New Scan Exceptions - YYYY-MM-DD]
```

Alternative:

```text
[AI-Assisted Addendum - Reviewed YYYY-MM-DD]
```

### Final Columns Updated

```text
Justifications for Exemptions
Mitigating Controls
```

### Master Tracker Evaluation Status Columns Updated

```text
Append Completed? = TRUE
```

### Exception Ledger Status Columns Updated

```text
Appended to Master? = TRUE
Append Date = YYYY-MM-DD
```

---

# Final End-to-End Workflow

```text
1. Run original merge script
   → Creates Master Tracker Evaluation
   → Creates Raw Scan Data Pool
   → Creates STIG ID Summary
   → Creates Plugin ID Summary
   → Creates Exception Ledger

2. Run generate_ai_packets.py
   → Creates one packet per IP with new unprocessed exceptions

3. Paste packets into STIG Deviation Justification Engineer Gem

4. Save Gemini responses to ai_responses/

5. Run import_ai_responses.py
   → Writes AI drafts into review columns

6. Review/edit drafts in Excel

7. Mark Ready to Append? = TRUE

8. Run append_approved_ai_drafts.py
   → Appends reviewed text into final Justifications and Mitigating Controls columns

9. Archive workbook/output as reviewed evidence
```

---

# Recommended Build Order

Use this order to keep the risk low:

```text
1. Add Exception Ledger to existing merge script
2. Add AI review columns to Master Tracker Evaluation
3. Generate packet files manually for 3–5 rows
4. Create/tune the second Gem
5. Create generate_ai_packets.py
6. Create import_ai_responses.py
7. Create append_approved_ai_drafts.py
```

The first milestone is not:

```text
AI writes my workbook
```

The first milestone is:

```text
Python correctly identifies new exceptions and creates clean AI-ready packets
```

---

# Planned Scripts

## Existing Script

```text
stig_deviation_merge.py
```

Expected updates:

- Continue creating the existing output workbook.
- Add `Exception Ledger`.
- Add AI review columns to `Master Tracker Evaluation`.
- Preserve existing Plugin ID Summary logic unless minor adjustment is required.

## New Script: generate_ai_packets.py

Purpose:

```text
Generate one AI packet per IP address with unprocessed exceptions.
```

Inputs:

```text
Output workbook
Master Tracker Evaluation sheet
Exception Ledger sheet
Optional system documentation excerpts
```

Outputs:

```text
ai_packets/*.md
```

Updates:

```text
Exception Ledger → AI Packet File
```

## New Script: import_ai_responses.py

Purpose:

```text
Import Gemini draft output back into review columns.
```

Inputs:

```text
Output workbook
ai_responses/*.json
```

Outputs:

```text
Updated workbook with AI draft columns populated
```

Updates:

```text
Master Tracker Evaluation review columns
Exception Ledger AI import status
```

## New Script: append_approved_ai_drafts.py

Purpose:

```text
Append reviewed AI draft text into final workbook columns.
```

Inputs:

```text
Output workbook with reviewed AI drafts
```

Outputs:

```text
Updated workbook with final columns appended
```

Updates:

```text
Justifications for Exemptions
Mitigating Controls
Append Completed?
Exception Ledger appended status
```

---

# Safety and Quality Controls

## Required Controls

- Preserve existing workbook values.
- Never overwrite final justification or mitigation text without review.
- Use stable `Exception_ID` values.
- Deduplicate findings.
- Track AI packet file and response file.
- Track whether AI output was imported.
- Track whether human review was completed.
- Track whether approved text was appended.
- Keep source references and assumptions separate from final drafted language.

## AI Output Rules

The AI should:

- Draft addenda only for new exceptions.
- Use only provided source material.
- Avoid unsupported claims.
- Flag missing documentation.
- Separate assumptions from drafted text.
- Provide a confidence rating.
- Return structured output.

---

# Open Questions

Use this section to track decisions while building.

## Packet Design

- [ ] Should packets be `.md`, `.json`, or both?
- [ ] Should packet files include SSP excerpts directly, or should those be pasted manually?
- [ ] Should packets be grouped by IP address, STIG ID, or exception?

Recommended answer:

```text
Use one .md packet per IP address, with structured JSON inside.
```

## Exception Ledger

- [ ] What exact fields should be used to generate `Exception_ID`?
- [ ] Should old exceptions be backfilled into the ledger?
- [ ] Should closed/pass findings appear in the ledger, or only active/open failures?

Recommended answer:

```text
Track active/open failures first. Add historical/backfill support later if needed.
```

## Review Workflow

- [ ] Who marks `Ready to Append?`
- [ ] Should append script require `Reviewer Status = Approved`?
- [ ] Should final appended text include "AI-Assisted" in the header?

Recommended answer:

```text
Require both Ready to Append? = TRUE and Reviewer Status = Approved.
```

## Documentation Sources

- [ ] Which system docs should be used first?
- [ ] Should SSP excerpts be stored in a folder?
- [ ] Should the packet generator eventually pull excerpts automatically?

Recommended answer:

```text
Start manual. Add automatic document retrieval later.
```

---

# First Milestone Checklist

- [ ] Create Git branch.
- [ ] Add `Exception Ledger` sheet to merge output.
- [ ] Add AI review columns to `Master Tracker Evaluation`.
- [ ] Generate stable `Exception_ID` values.
- [ ] Mark new exceptions as `Needs AI Draft? = TRUE`.
- [ ] Create 3–5 manual test packets.
- [ ] Create the `STIG Deviation Justification Engineer` Gem.
- [ ] Test Gemini output format.
- [ ] Tune Gem instructions.
- [ ] Create `generate_ai_packets.py`.
- [ ] Create `import_ai_responses.py`.
- [ ] Import test responses into review columns.
- [ ] Review/edit AI drafts.
- [ ] Create `append_approved_ai_drafts.py`.
- [ ] Append approved drafts into final columns.
- [ ] Validate workbook output.
- [ ] Commit working milestone.

---

# Notes

This workflow is intentionally conservative.

The purpose is not to let AI make final compliance determinations. The purpose is to reduce manual writing burden while preserving:

- traceability
- reviewer control
- source references
- workbook integrity
- repeatable automation
- audit-friendly records
