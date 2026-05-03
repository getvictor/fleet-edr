# Stale implementation references

**Cadence:** monthly
**Time budget:** 30-45 min
**Trigger mode:** manual

## Why this matters

While work is in flight, docs accumulate references to the in-progress implementation: "phase 6", "in the `phase7-testkit`
branch", "the new alerts table will be added in step 3", "see `claude/mvp/plan.md` for context". Once the work lands, those
references become misleading: a future reader treats them as part of the permanent architecture and goes hunting for files or
phases that no longer exist or never did.

The current best-practices doc still has at least one such reference (`docs/best-practices.md:222` mentions "phase 5 in favour of
code-level validation"). That's the canonical example.

## Scope

Committed prose only - `docs/`, `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, per-package READMEs, ADRs. Excludes
`claude/` (which is gitignored scratch and may legitimately reference plans).

## Patterns to find and triage

| Pattern | What to do |
|---|---|
| `phase \d+`, `step \d+`, `iteration \d+` | If the phase is complete, rewrite the sentence around the *outcome*, not the journey. If incomplete, the doc shouldn't have it yet. |
| Branch names (`phase7-testkit`, `phase6-cleanup`) | Replace with the file or commit that survived merge, or delete. |
| `claude/<topic>/plan.md` references in committed docs | Strip; `claude/` is gitignored, so the link is broken for everyone but the author. |
| "TODO: implement X in the next phase" | Convert to GitHub issue or delete. Committed docs should describe what *exists*. |
| "Will be added", "coming soon", "not yet wired" | If the feature shipped, update the doc; if it hasn't, link to a tracking issue or delete. |
| References to renamed packages / contexts | Sweep against ADR-0004 boundary names. |

## Steps

1. Run grep patterns across the scope:
   ```bash
   git grep -niE 'phase [0-9]|phase[0-9]|step [0-9] of|iteration [0-9]' -- ':!claude/' ':!tmp/'
   git grep -niE 'will be|coming soon|not yet wired|todo:' -- ':!claude/' ':!tmp/' '*.md'
   git grep -nE 'claude/' -- '*.md' ':!claude/' ':!tmp/'
   ```
2. For each hit, decide: **rewrite around outcome** / **delete** / **convert to issue**.
3. Confirm by also reading the surrounding paragraph: "phase 5" might be a legitimate reference to the *fifth phase of an attack
   chain*, not a project phase.
4. Open one PR titled `Stale implementation references sweep YYYY-MM-DD`.

## Output

A PR. If no findings, append `YYYY-MM-DD: stale-implementation-references - no findings` to
`docs/maintenance/log.md`.

## Prompt template

```
Run the stale-implementation-references sweep defined in
docs/maintenance/tasks/stale-implementation-references.md.

Run these greps and triage every hit (some may be legitimate references to attack-chain phases or numbered
list items in technical content; use judgment):

  git grep -niE 'phase [0-9]|phase[0-9]|step [0-9] of|iteration [0-9]' -- ':!claude/' ':!tmp/'
  git grep -niE 'will be|coming soon|not yet wired|todo:' -- ':!claude/' ':!tmp/' '*.md'
  git grep -nE 'claude/' -- '*.md' ':!claude/' ':!tmp/'

For each genuine finding: rewrite the sentence around the surviving outcome (no "phase X" wording),
delete it, or convert to a GitHub issue if it's a real TODO. Do NOT silently delete content that may
still be load-bearing - if unsure, leave the line and flag it for human review in the PR description.

Open one PR with the format above. Do not exceed 45 minutes.
```

## Definition of done

- [ ] All grep patterns executed and every hit triaged (no skipped lines).
- [ ] PR opened or "no findings" logged with date.
- [ ] No reference to gitignored `claude/` paths remains in committed docs.
