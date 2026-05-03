# ADR audit

**Cadence:** quarterly
**Time budget:** 90-120 min
**Trigger mode:** manual

## Why this matters

ADRs encode load-bearing decisions ("single Go module + `internal/`", "modular monolith with bounded contexts", "Apple Silicon +
macOS 13+ MVP", "standalone product, not Fleet-integrated"). Two failure modes are common:

1. **Silent supersession** - the team reverses a decision in a PR review or Slack thread, but never updates the ADR. New
   contributors then follow the old ADR and write code that conflicts with current direction.
2. **Missing ADRs** - a non-trivial decision (e.g. "all metrics go through OTel, never Prometheus") gets repeated in code reviews
   for a year before someone writes it down. Until it's in an ADR, every contributor relearns it from scratch.

Both compound. ADRs that are continuously curated are one of the highest-leverage maintenance investments in any codebase.

## Scope

`docs/adr/` and any place that references an ADR by number (search `git grep -n 'ADR-'`).

## Steps

### 1. Status check

For each existing ADR:

- Re-read it as if encountering for the first time. Does it still describe how the codebase works *today*?
- Check `git log --since=3.months docs/adr/` - were any ADRs amended? Why? Does the body match the amendment?
- Check `git grep -nE 'see ADR-[0-9]+|ADR-[0-9]+' -- ':!docs/adr/' ':!claude/'`. References from prose / code should still be
  accurate.
- If the decision is no longer in force, mark `Status: Superseded by ADR-XXXX` (or `Status: Deprecated`). Never silently delete an
  ADR - keep the historical record.

### 2. Gap check

Go through these candidate decision domains and ask: is there an ADR for it? If not, should there be?

| Domain | Existing? | Decision worth recording? |
|---|---|---|
| Single Go module | ADR-0001 | yes |
| Apple Silicon + macOS 13+ MVP | ADR-0002 | yes |
| Standalone product (not Fleet) | ADR-0003 | yes |
| Modular monolith / bounded contexts | ADR-0004 | yes |
| Test layering (unit / per-context / cross-context) | maybe | check |
| OTel-only metrics (no Prometheus /metrics) | not yet | likely yes |
| Embedded UI (`server/ui/dist/` via embed.go) | not yet | check |
| `server/testdb/full.Open` as the integration-test seam | not yet | likely yes |
| Co-Authored-By trailers policy | not yet | possibly (it's in MEMORY/CLAUDE.md only) |
| AI-tooling-as-code (CLAUDE.md, skills, commands committed) | not yet | possibly |

For each gap that's worth recording, file an issue tagged `adr` describing the decision, the constraints behind it, and the
alternatives. Don't write the ADR during this audit unless it's trivial - it's a separate piece of writing that benefits from a
focused session.

### 3. Index hygiene

Update `docs/adr/README.md` if any ADR changed status. The index should always be the source of truth for "which ADRs are active".

## Output

- Edits to existing ADRs (status updates, supersession notes).
- Issues filed for ADR gaps.
- Updated `docs/adr/README.md`.
- A short note in the audit PR body summarising "what changed and why".

## Prompt template

```
Run the ADR audit defined in docs/maintenance/tasks/adr-audit.md.

Scope: docs/adr/*.md and any committed file that references "ADR-NNNN".

For each existing ADR:
1. Read it. Compare it to current code reality (don't guess - verify with grep / Read).
2. If the ADR is now stale, update its Status line and add a note linking to the superseding decision.
   Don't delete content; ADRs are historical records.
3. Check git log of the last 3 months for amendments and confirm body matches.

Then check the gap list in the task file. For each candidate domain without an ADR, decide whether it
warrants one. File issues for the gaps you'd recommend; do NOT write the new ADR in this session - that
needs its own focused write-up.

Update docs/adr/README.md to reflect any status changes. Open one PR.

Time budget: 2 hours. If a single ADR turns out to need a major rewrite, file it as a separate issue
and move on.
```

## Definition of done

- [ ] Every existing ADR re-read against current reality.
- [ ] Stale ADRs marked Superseded / Deprecated, not deleted.
- [ ] Gap list reviewed; issues filed for any decisions that warrant new ADRs.
- [ ] `docs/adr/README.md` reflects current status.
- [ ] Dated entry in `docs/maintenance/log.md`.
