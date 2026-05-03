# Architecture drift (semantic)

**Cadence:** quarterly
**Time budget:** 90 min
**Trigger mode:** manual

## Why this matters

`arch-go.yml` is the structural fitness function: it catches cross-context imports, internal-package leaks, and layering
violations on every PR. What it can NOT catch:

- **Conceptual coupling** - context A "knowing" the schema or invariants of context B even though it imports cleanly through
  the `api/` boundary. Common pattern: rebuilding a stripped-down version of B's domain model on A's side.
- **Drift in `internal/` boundaries** - a package that was intended to be private to one context slowly accumulates callers from
  outside.
- **God-tables / god-services** - a single struct or table that has become the join point of every context, undoing the bounded-
  context separation.
- **Test cross-pollination** - integration tests in one context's `tests/` package quietly poking at another context's tables.
- **Migration ordering** - schema changes that assume a context boundary that no longer holds.
- **Abstraction reversal** - interface in package A satisfied only by an implementation in package B that depends on A. The
  imports are clean; the dependency is a circle.

This task is the human-judgment counterpart to `arch-go`.

## Scope

`server/identity/`, `server/endpoint/`, `server/rules/`, `server/response/`, `server/detection/`, `internal/`, plus
`server/testdb/full/` (cross-context test fixtures).

## Steps

### 1. Re-read ADR-0004

The bounded-context decision is the yardstick. Before scrutinising drift, refresh the intent: what does each context own? What are
the legitimate cross-context interactions through `api/`?

### 2. Boundary heat map

```bash
# What does each context import from another?
for ctx in identity endpoint rules response detection; do
  echo "=== $ctx ==="
  grep -rE '"github.com/[^"]+/server/[^/]+/' server/$ctx --include='*.go' \
    | grep -vE "/server/$ctx/" | sed 's/.*\/server\///' | sort -u
done
```

Look for surprising entries (e.g. `detection` importing from `endpoint/api`'s deeper paths than just the top-level api package).

### 3. Conceptual coupling check

For each context, pick the 2-3 most commonly imported types from its `api/` package. Now grep for those types' fields *being read
by the consumer*. If the consumer reads internal-looking fields (alert IDs as strings without going through helpers, raw timestamps
without going through accessors), the API is leaking the implementation. Note for refactor.

### 4. God-struct check

```bash
# Largest types in api/
for f in server/*/api/*.go; do
  go doc -all "$f" 2>/dev/null | head -50
done | grep -A1 'type.*struct' | head -40
```

If a single struct in any context's `api/` is referenced by all four other contexts and is growing, that's a god-struct in the
making. File for refactor.

### 5. Test-fixture drift

`server/testdb/full/full.go` builds test fixtures across contexts. If it's grown opinions about every context's invariants, those
opinions need to be re-confirmed against the contexts' real schemas. A fixture that "happens to set this field because it used to
matter" is a future-bug landmine.

### 6. Migration ordering

`grep -rE 'schema/migrations|server/.*/internal/mysql/migrations' . --include='*.go'`. Confirm migration files for one context
don't reference another context's tables. If they do (sometimes legitimate for FKs), that's a real cross-context coupling and
deserves an ADR amendment, not silence.

## Output

- One PR per refactor that's small enough to land safely.
- Issues filed for each refactor that's not.
- A short note in the audit summary on whether ADR-0004 still describes intent or needs amending.

## Prompt template

```
Run the architecture-drift audit defined in docs/maintenance/tasks/architecture-drift.md.

Step 1 - re-read docs/adr/0004-modular-monolith-bounded-contexts.md.

Step 2 - build the boundary heat map per the task file. Flag any cross-context imports beyond api/.

Step 3 - for each context, sample 2-3 popular api/ types. Check that consumers go through helpers
rather than poking internal-looking fields directly.

Step 4 - find god-struct candidates in api/ packages.

Step 5 - review server/testdb/full/full.go for fixture invariants that have outlived their context.

Step 6 - check migration files for cross-context references.

For each finding, decide: small enough to refactor in this PR / file an issue / amend ADR-0004 / accept
and document the exception. Open one PR for the refactors and a tracking issue listing the rest.

Hard rule: if no findings rise above noise, write that finding into docs/maintenance/log.md with date.
The "no findings" outcome is itself signal - it means arch-go and the test layout are doing their job.
```

## Definition of done

- [ ] Boundary heat map captured (paste into PR body or log).
- [ ] Each finding has a decision (refactor / issue / accept).
- [ ] If ADR-0004's intent has shifted, an amendment is filed.
- [ ] Dated entry in `docs/maintenance/log.md`.
