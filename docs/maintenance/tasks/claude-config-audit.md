# Claude config audit

**Cadence:** quarterly **Time budget:** 60 min **Trigger mode:** manual

## Why this matters

`.claude/` (settings, skills, slash commands, hooks) and the user-level `~/.claude/` config now shape every coding session as strongly as `lefthook.yml` shapes every commit. Drift here is invisible - there's no compiler, no test, and the harness will silently obey stale rules. A skill that references a file that no longer exists, a hook that runs a deleted task, or a permission that was sensible once but now masks a security warning all degrade the agent without anyone noticing.

This is a 2025-2026-era maintenance domain that didn't exist when most "best practices" docs were written.

## Scope

`.claude/` is gitignored in this repo (see `.gitignore`), so this audit operates on each maintainer's local checkout, not on a PR. The same reviewer running this task quarter after quarter is the right pattern; the audit log entry records the date and "no findings" or a summary of changes.

Files in scope (all per-maintainer, none committed):

- `.claude/settings.local.json` (project-scoped overrides)
- `.claude/commands/` (project-scoped slash commands)
- `.claude/skills/` (project-scoped skills)
- `.claude/scheduled_tasks.lock` (informational)
- Any hook entries in those settings files

User-level `~/.claude/` (settings, MEMORY index, user-level skills) is out of scope unless explicitly requested - that's cross-project.

## Steps

### 1. Permissions hygiene

Read `.claude/settings.local.json`. For each `allow` entry:

- Is it still needed (does the matching command actually run during sessions)?
- Is it overly broad (`Bash(*)` instead of `Bash(go test:*)`)?
- Does it mask a check that should require confirmation (e.g. `Bash(git push:*)` without scope)?

Tighten or remove.

### 2. Hook hygiene

For each hook entry:

- Does the script / command it invokes still exist?
- Is it firing on the right event? (PreToolUse vs PostToolUse vs Stop semantics changed at one point.)
- Run a session and confirm the hook actually fires (look for output / errors).

Stale hooks should be deleted, not commented out.

### 3. Slash-command and skill inventory

For each file in `.claude/commands/` and `.claude/skills/`:

- Does the description still match what the command does?
- Are referenced files / scripts still present?
- Is it ever invoked (check session history if available)? An unused slash command isn't free - it adds to the model's selection space and confuses the human user.
- If the command would now be better expressed as a built-in skill (e.g. `/ai-review-fixes-edr` is already a skill - no need for a duplicate command), consolidate.

### 4. Cross-check with `~/.claude/MEMORY.md`

The user-level memory is loaded into every session. If a project-level skill or command duplicates guidance that's already in memory, that's redundancy noise. Pick one.

### 5. Settings shape

Skim the schema docs (or run `claude config --help`) for any new settings that have been added since the last audit. Examples: new hook events, new permission shapes, new statusline options. The harness changes; the config can lag.

## Output

A PR titled `Claude config audit YYYY-Q\d`. PR body lists every change with one-line rationale.

## Prompt template

```text
Run the Claude config audit defined in docs/maintenance/tasks/claude-config-audit.md.

Step 1 - read .claude/settings.local.json. For each allow rule, decide: keep / tighten scope / remove.
Bias toward narrower scopes. Remove any rule whose target command no longer exists.

Step 2 - for each hook, verify the script/command exists, the event is correct, and the hook is
actually firing (run a quick session).

Step 3 - list .claude/commands/ and .claude/skills/. For each, verify referenced files exist,
description matches behaviour, and there's no duplication with a built-in skill or with
~/.claude/MEMORY.md guidance.

Step 4 - check Claude Code release notes / docs for new settings since the last audit. Flag anything
that would benefit this repo but isn't yet wired up.

Open one PR. Time budget 60 minutes.

Important: do NOT loosen permissions during this sweep. Tightening is fine; loosening needs a separate
discussion with the user.
```

## Definition of done

- [ ] Every `allow` entry justified or removed.
- [ ] Every hook verified to fire and reference a real script.
- [ ] Every slash command and skill verified for accurate description and no duplication.
- [ ] Permissions only tightened, never loosened, in this sweep.
- [ ] Dated entry in `docs/maintenance/log.md`.
