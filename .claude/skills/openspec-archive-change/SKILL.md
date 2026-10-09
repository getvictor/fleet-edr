---
name: openspec-archive-change
description: Archive a completed change in the experimental workflow. Use when the user wants to finalize and archive a change after implementation is complete.
license: MIT
compatibility: Requires openspec CLI.
metadata:
  author: openspec
  version: "1.0"
  generatedBy: "1.3.1"
---

Archive a completed change in the experimental workflow.

**Input**: Optionally specify a change name. If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show only active changes (not already archived).
   Include the schema used for each change if available.

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Check artifact completion status**

   Run `openspec status --change "<name>" --json` to check artifact completion.

   Parse the JSON to understand:
   - `schemaName`: The workflow being used
   - `artifacts`: List of artifacts with their status (`done` or other)

   **If any artifacts are not `done`:**
   - Display warning listing incomplete artifacts
   - Use **AskUserQuestion tool** to confirm user wants to proceed
   - Proceed if user confirms

3. **Check task completion status**

   Read the tasks file (typically `tasks.md`) to check for incomplete tasks.

   Count tasks marked with `- [ ]` (incomplete) vs `- [x]` (complete).

   **If incomplete tasks found:**
   - Display warning showing count of incomplete tasks
   - Use **AskUserQuestion tool** to confirm user wants to proceed
   - Proceed if user confirms

   **If no tasks file exists:** Proceed without task-related warning.

4. **Archive with the OpenSpec CLI, never by hand**

   This repo batches archives at release (CLAUDE.md, `docs/release-checklist.md`): a merged change stays in
   `openspec/changes/<name>/` until the release archive step. Outside that step, stop and say so rather than archiving one change.

   For the release batch run `task release:archive -- --dry-run`, then `task release:archive`, which applies
   `openspec archive <name> -y` in the order `spectrace archive-order` computes. To archive one named change on the user's explicit
   request, run `openspec archive "<name>" -y`. Pass `--skip-specs` only when the canonical spec was already updated by hand. Never
   edit `openspec/specs/**` with ordinary file edits, and never move a change folder into `openspec/changes/archive/`.

5. **Display summary**

   Show archive completion summary including:
   - Change name
   - Schema that was used
   - Archive location
   - Whether delta specs were merged
   - Note about any warnings (incomplete artifacts/tasks)

**Output On Success**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Specs:** merged by openspec archive (or "No delta specs")

All artifacts complete. All tasks complete.
```

**Guardrails**
- Always prompt for change selection if not provided
- Use artifact graph (openspec status --json) for completion checking
- Don't block archive on warnings - just inform and confirm
- Archive only through `openspec archive` or `task release:archive`; never hand-edit `openspec/specs/**` or move folders into `archive/`
- Show clear summary of what happened
