# Stale implementation references

**Cadence:** monthly
**Time budget:** 60-90 min (scope spans prose, code comments, and committed `.claude/` files)
**Trigger mode:** manual

## Why this matters

While work is in flight, docs and code comments accumulate references to the in-progress implementation: "phase 6", "in the
`phase7-testkit` branch", "the new alerts table will be added in step 3", "see `claude/mvp/plan.md` for context". Once the
work lands, those references become misleading: a future reader treats them as part of the permanent architecture and goes
hunting for files or phases that no longer exist or never did. Code comments rot the same way as prose, especially package
docs (`doc.go`), API surface comments (`type Foo interface { ... }` blocks), and test names that pin a "Phase N" contract that
has since become "the contract".

A canonical past example: `docs/best-practices.md` once read "the FK was dropped in phase 5 in favour of code-level validation".
The 2026-05-03 sweep rewrote it to "the FK was dropped in favour of code-level validation" - same outcome, no journey. The
same sweep cleared ~90 phase-numbered code comments under `agent/`, `extension/`, `server/`, `ui/`, `test/integration/`, plus
`arch-go.yml`, `Taskfile.yml`, and the agent LaunchDaemon plist.

## Scope

Three buckets, all in scope:

1. **Committed prose**: `docs/`, `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, per-package READMEs, ADRs.
2. **Committed code comments**: `agent/`, `server/`, `ui/`, `extension/`, `test/`, `scripts/`, plus build configs (`arch-go.yml`,
   `Taskfile.yml`, `.github/workflows/*`) and the agent's LaunchDaemon plist. Includes `doc.go`, package-level comments,
   interface and field comments, test-function comments, and string fixtures that bake in phase wording (e.g.
   `"agent_version": "phase8-..."`).
3. **Committed `.claude/`**: this repo tracks `.claude/commands/opsx/*.md` and `.claude/skills/openspec-*/SKILL.md`. They drift
   the same way prose does. The user-level `~/.claude/` and the gitignored project-level `.claude/scheduled_tasks.lock` are
   out of scope.

Excludes the gitignored `claude/` (singular, no leading dot) topic-plan tree and `tmp/`. Also excludes
`openspec/changes/<change-name>/` trees: OpenSpec change proposals use phase numbering as a planning device for
in-flight work, by design. They get archived under `openspec/archive/` when complete; do not rewrite their
phase headings while a change is active. If an archived change has phase numbering that has rotted (e.g.
documented work that landed and was renamed), that is in scope.

## Patterns to find and triage

| Pattern | What to do |
|---|---|
| `phase \d+`, `step \d+`, `iteration \d+` in prose or code comments | If the phase is complete, rewrite the sentence around the *outcome*, not the journey. If incomplete, the doc/comment shouldn't have it yet. |
| Branch names (`phase7-testkit`, `phase6-cleanup`) | Replace with the file or commit that survived merge, or delete. |
| `claude/<topic>/plan.md` references in committed prose or code | Strip; `claude/` is gitignored, so the link is broken for everyone but the author. |
| "TODO: implement X in the next phase" | Convert to GitHub issue or delete. Committed content should describe what *exists*. |
| "Will be added", "coming soon", "not yet wired" | If the feature shipped, update the doc; if it hasn't, link to a tracking issue or delete. |
| References to renamed packages / contexts | Sweep against ADR-0004 boundary names. |
| Test-fixture strings that bake in phase wording (e.g. `"agent_version": "phase8-..."`, `wantBody: "phase6"`) | Rename to a phase-neutral marker; keep the test logic identical. |
| Testplan section IDs (`Section A.B`, `qa: Sections C + D + F.4`, `D.3a OIDC reauth — ...`) in test names, describe blocks, comments, file names, script names, or fixture constants (alert titles, `TEST_HOST_ID = "qa-host-d3"`, `BG_PASSWORD = "qa-d3-..."`). | Rewrite around what the test pins or what the file holds. File renames done via `git mv` preserve blame; npm scripts + GHA references must be updated to match. |

## Steps

1. Run grep patterns across the scope. The first runs over every tracked file (prose + code + committed `.claude/`); the
   second is markdown-scoped because "will be" is too noisy in Go/TS/Swift; the third catches any path-style `claude/` link
   that leaks into committed prose or code comments; the fourth catches testplan section IDs baked into committed code.
   ```bash
   git grep -niE 'phase [0-9]|phase[0-9]|step [0-9] of|iteration [0-9]' -- ':!claude/' ':!tmp/' ':!openspec/changes/'
   git grep -niE 'will be|coming soon|not yet wired|todo:' -- ':!claude/' ':!tmp/' ':!openspec/changes/' '*.md'
   git grep -nE 'claude/' -- ':!claude/' ':!tmp/' ':!.claude/' ':!openspec/changes/'
   git grep -niE 'Section [A-G]\.[0-9]|Sections [A-G]\.[0-9]' -- ':!claude/' ':!tmp/' ':!openspec/changes/'
   # Also sweep tracked filenames + npm scripts for the same taxonomy:
   git ls-files | grep -E 'section-[a-g][0-9]|sections-[a-g]' || true
   grep -nE '"qa:[a-g][0-9]?":' package.json test/e2e/package.json 2>/dev/null || true
   ```
   The third grep excludes the committed `.claude/` tree because OpenSpec slash commands legitimately reference
   `.claude/` paths in their own bodies; sweep that tree manually instead. All four greps exclude `openspec/changes/`
   because OpenSpec change proposals use phase numbering as in-flight planning structure; sweep `openspec/archive/`
   instead when an archived change has rotted. The fourth grep + the ls-files / package.json checks catch the
   QA-testplan-section-ID flavour of rot (`Section D.3`, `qa: Sections C + D + F.4`, `section-a6-allowlist.spec.ts`,
   `qa:a6`); the row in the patterns table above explains how to rewrite each hit. Rename files via `git mv` so blame
   survives; update every consumer (npm scripts, `scripts/*.sh`, `.github/workflows/*.yml`, gitignored QA-plan doc
   under `claude/` if present) in the same PR.
2. For each hit, decide: **rewrite around outcome** / **delete** / **convert to issue**.
3. Confirm by also reading the surrounding paragraph or function: "phase 5" might be a legitimate reference to the *fifth
   phase of an attack chain*, not a project phase. `Step 3 of 7` in `scripts/qa/attack-runbook.sh` is rendered to the
   operator console at runtime; that's a legitimate use of step numbering.
4. Open one PR titled `Stale implementation references sweep YYYY-MM-DD`.

## Output

A PR. If no findings, append `YYYY-MM-DD: stale-implementation-references - no findings` to
`docs/maintenance/log.md`.

## Prompt template

```
Run the stale-implementation-references sweep defined in
docs/maintenance/tasks/stale-implementation-references.md.

Scope: committed prose (docs/, README.md, ADRs, *.md), committed code comments
(agent/, server/, ui/, extension/, test/, scripts/, build configs, plist),
plus committed .claude/ (commands and skills under .claude/).

Run these greps and triage every hit (some may be legitimate references to attack-chain phases,
numbered list items, runtime per-step header rendering, or OpenSpec change planning; use judgment):

  git grep -niE 'phase [0-9]|phase[0-9]|step [0-9] of|iteration [0-9]' -- ':!claude/' ':!tmp/' ':!openspec/changes/'
  git grep -niE 'will be|coming soon|not yet wired|todo:' -- ':!claude/' ':!tmp/' ':!openspec/changes/' '*.md'
  git grep -nE 'claude/' -- ':!claude/' ':!tmp/' ':!.claude/' ':!openspec/changes/'
  git grep -niE 'Section [A-G]\.[0-9]|Sections [A-G]\.[0-9]' -- ':!claude/' ':!tmp/' ':!openspec/changes/'
  git ls-files | grep -E 'section-[a-g][0-9]|sections-[a-g]' || true
  grep -nE '"qa:[a-g][0-9]?":' package.json test/e2e/package.json 2>/dev/null || true

For each genuine finding: rewrite the sentence around the surviving outcome (no "phase X" or
"Section A.B" wording), delete it, or convert to a GitHub issue if it's a real TODO. For
test-fixture literals or constants that bake in phase/section wording, rename to a neutral marker
without changing test logic. For files/scripts named after sections, `git mv` to a descriptive name
and update every consumer in the same PR (npm scripts, `scripts/*.sh`, `.github/workflows/*.yml`).
Do NOT silently delete content that may still be load-bearing - if unsure, leave the line and flag
it for human review in the PR description.

Open one PR with the format above. Do not exceed 90 minutes.
```

## Definition of done

- [ ] All grep patterns executed and every hit triaged across prose, code comments, and committed `.claude/`.
- [ ] PR opened or "no findings" logged with date.
- [ ] No reference to gitignored `claude/` paths remains in committed prose or code.
- [ ] No `Phase N` reference remains in package docs, interface comments, or test names that document the *current* contract.
- [ ] No `Section A.B` testplan ID remains in tracked file names, npm script names, test/describe blocks, or fixture
  constants that document the *current* contract; renamed files use `git mv` so blame survives, and every consumer
  (npm scripts, shell scripts, CI workflows, gitignored plan docs) is updated in the same PR.
