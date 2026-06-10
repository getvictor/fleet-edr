# MEMORY.md and CLAUDE.md audit

**Cadence:** monthly **Time budget:** 30-45 min **Trigger mode:** manual

## Why this matters

`CLAUDE.md` (project-level, committed) and the per-user, per-project `MEMORY.md` (under `~/.claude/projects/<project-id>/memory/MEMORY.md`, where `<project-id>` is your absolute checkout path with `/` replaced by `-`) shape every agent action invisibly. Unlike code or docs, nothing fails when these go stale: the agent simply follows outdated guidance and produces subtly wrong work. A monthly pass is the cheapest insurance against silent regressions in agent behaviour.

This is doubly important here because MEMORY.md contains project facts dated to specific decisions ("decided 2026-04-18", "VM IP 192.168.64.5") that change without notice.

## Scope

- `CLAUDE.md` at the repo root
- Per-package `CLAUDE.md` files if any exist (currently none - `git ls-files '**/CLAUDE.md'` to confirm)
- `~/.claude/projects/<project-id>/memory/MEMORY.md` and the per-topic files it indexes

User-level `~/.claude/CLAUDE.md` is out of scope unless explicitly requested - that's per-user.

## Steps

### 1. CLAUDE.md (project)

Re-read the whole file as if encountering it for the first time. For each rule or section:

- **Still true?** If a "we use OTel meter, not Prometheus" rule is now contradicted by code, that's a flag.
- **Still useful?** If a guideline is being followed automatically (lefthook formats the code), it doesn't need to be asserted in CLAUDE.md too.
- **Still scoped right?** Project-specific guidance should live here; user-specific preferences live in `~/.claude/CLAUDE.md`. If there's leakage in either direction, fix.

### 2. MEMORY.md (per-user, per-project)

Open the index and each pointer file. For each entry:

- **Verify dates / specifics**: VM IP addresses, decision dates, branch names. If "phase7-testkit" is now merged, the entry may need to point to a file rather than the branch.
- **Verify references**: if the entry says "see `docs/best-practices.md`", confirm the line still exists.
- **Verify "what NOT to save" rule**: if any entry contains code patterns, file paths derivable from the repo, or git history, it shouldn't be in memory - delete.
- **Decay check**: project memories ("merge freeze 2026-03-05") expire. After the date passes, the entry should be removed unless it now serves as historical context for an ADR.

### 3. Cross-check

If MEMORY.md says X and CLAUDE.md says Y on the same topic, one of them is wrong. Reconcile. If MEMORY.md restates something that's already in CLAUDE.md, prefer keeping it in CLAUDE.md (it's the public source of truth); delete from MEMORY.md.

### 4. Format hygiene

`MEMORY.md` is loaded into every session. The first 200 lines of it are not free. Trim, dedupe, and keep entries to one line in the index. Detail belongs in the per-topic files it points to.

## Output

- A PR for any `CLAUDE.md` changes (it's committed).
- Direct edits to MEMORY.md (it's per-user, not committed).
- A dated entry in `docs/maintenance/log.md` on every run, whether the audit found changes or not - the log is the audit trail proving the cadence is being honoured.

## Prompt template

```text
Run the MEMORY/CLAUDE audit defined in docs/maintenance/tasks/memory-and-claudemd-audit.md.

Step 1 - read CLAUDE.md at the repo root. For each rule, verify it's still true (cross-check
with code), still useful (not redundant with lefthook / CI), and properly scoped (project, not user).

Step 2 - read your per-user MEMORY.md at ~/.claude/projects/<project-id>/memory/MEMORY.md (where
<project-id> is your absolute repo path with / replaced by -) and every file it indexes. Verify
dates, IPs, branch names, and references. Delete entries that are now stale, duplicate CLAUDE.md,
or violate the "do not save derivable info" rule.

Step 3 - reconcile any conflict between MEMORY.md and CLAUDE.md. CLAUDE.md wins (public source of
truth). MEMORY.md keeps only context that benefits future sessions and isn't derivable from code.

Step 4 - trim MEMORY.md index entries to one line each. The first 200 lines is the budget.

CLAUDE.md changes go in a PR. MEMORY.md edits are direct (per-user, not committed). Log both in
docs/maintenance/log.md.

Time budget 45 minutes. Do NOT add new rules in this sweep - additions go through normal review.
```

## Definition of done

- [ ] Every CLAUDE.md rule re-verified against code.
- [ ] Every MEMORY.md entry verified or removed.
- [ ] No conflict between the two; no duplication.
- [ ] MEMORY.md index entries are one line each.
- [ ] PR opened for CLAUDE.md changes.
- [ ] Dated entry appended to `docs/maintenance/log.md` (mandatory on every run, regardless of findings).
