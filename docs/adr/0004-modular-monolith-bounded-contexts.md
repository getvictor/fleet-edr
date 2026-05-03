# 0004. Modular monolith with bounded contexts

- Status: Implemented
- Date: 2026-05-01
- Deciders: getvictor

> Migration completed 2026-05-03 across phases 1-6. See
> `claude/modular-monolith/phase[1-6].md` for the per-phase plans
> and outcomes. Phase 7 added per-context `testkit/` packages so
> tests reach for a coordinated test surface separate from production
> wiring; phase 8 tightened arch-go to its strict-mode form. arch-go
> (`arch-go.yml` + `test/arch/arch_test.go`) enforces the
> bounded-context import rules in CI as a hard-fail gating check.
> See `docs/architecture-maturity.md` for the audit of what's
> enforced where, plus the graduation-criteria checklist for when to
> invest in heavier patterns (ACL packages, event-driven cross-context
> calls, database-per-context, separate-process split).

## Context

`server/` has grown from a single ingestion handler to roughly two dozen
packages spanning event ingest, process-graph materialisation, detection
rule evaluation, alert lifecycle, command queue, host enrollment, operator
identity, and an admin API surface. Today most of these packages share a
single `server/store/` god-package that owns six of the seven core tables
(`events`, `processes`, `hosts`, `alerts`, `alert_events`, `commands`); a
`server/api/` god-package serves hosts, alerts, and commands endpoints from
one `Handler`; and `server/admin/` straddles enrollment + policy + commands
+ detection-rule routes. Sixteen files under `server/` import `server/store`
directly.

The product ambition (per the project's positioning notes) is to compete
with CrowdStrike Falcon and SentinelOne on detection latency, throughput,
and content velocity. Two forces shape the architectural choice:

1. **Detection content has to ship faster than the binary.** A best-in-class
   EDR pushes new rules daily through a content channel, not on a server
   release train. Today's rules live as Go files in `server/detection/rules/`,
   imported into the engine at compile time, with no separation between
   "rule executor" and "rule catalog."
2. **The hot path (event arrives -> alert is emitted) is the competitive
   moat and must remain a single-process, single-transaction, low-allocation
   pipeline.** Splitting that pipeline across narrowly scoped contexts (one
   per table) would force interface hops, type translations, and lost
   transactional control on the most performance-sensitive path in the
   system.

The Fleet codebase has converged on a "modular monolith with bounded
contexts" pattern documented at
`fleetdm/fleet/docs/Contributing/architecture/modular-monolith/README.md`.
The pattern is generally applicable: pick a small number of cohesive
contexts, give each one a vertical slice (handlers -> service -> data),
forbid imports across context internals, mediate cross-context calls
through a public `api/` package. Apply that pattern here, but with the
EDR-specific twist that the hot pipeline stays as one large context
rather than being fragmented along table lines.

## Decision

Adopt a modular-monolith layout with **five bounded contexts** under
`server/`:

| Context     | Owns                                                                   |
|-------------|------------------------------------------------------------------------|
| `detection` | Hot pipeline. Tables: `events`, `processes`, `hosts`, `alerts`, `alert_events`. |
| `rules`     | Detection content + blocklist policy. Tables: `policies`.              |
| `response`  | Agent commands. Tables: `commands`.                                    |
| `endpoint`  | Host enrollment + host-token verification. Tables: `enrollments`.       |
| `identity`  | Operator users, sessions, login. Tables: `users`, `sessions`.           |

Each context follows this layout:

```text
server/<context>/
  api/                  # public types + interfaces (importable by any context)
  bootstrap/            # New(deps), ApplySchema, RegisterRoutes (server/cmd/* + tests only)
  internal/             # private; Go compiler blocks imports from outside
    <module>/           # service, mysql, middleware, engine, etc.
    tests/              # per-context integration tests
```

The top-level `server/<context>/` directory contains zero Go files, so
`import "server/<context>"` fails. Internal modules are protected by Go's
language-level `internal/` rule from day one (consistent with ADR-0001's
choice to put shared code at the repo-root `internal/`). Cross-context
calls go through `<other>/api`. Cross-context HTTP composition happens
at the binary entrypoints under `server/cmd/*` (today
`server/cmd/fleet-edr-server/main.go` and
`server/cmd/fleet-edr-ingest/main.go`), not inside any context. No
cross-context transactions, and no cross-context foreign keys after
the migration completes; one such FK exists in the current schema
(`fk_alerts_updated_by` linking `alerts.updated_by` to `users.id`)
and is dropped during phase 5, replaced by code-level validation in
the alert-update handler.

Three test layers, each with a clear scope and import boundary:

1. Per-package unit tests (default tag) co-located with code.
2. Per-context integration tests at `<context>/internal/tests/`,
   `//go:build integration`, scoped to one context's public surface.
3. Cross-context integration tests at `test/integration/`,
   `//go:build integration`, exercising scenarios that span contexts.

The Go compiler enforces test-package isolation for layers 2 and 3 via
the `internal/` rule. Architecture lint (`arch-go`, programmatic API
invoked from `go test ./test/arch/...`) covers the rules Go's compiler
cannot express, namely: which contexts may import which other contexts'
`api/` packages, that platform packages may not import contexts, and
that `bootstrap/` packages are imported only by `server/cmd/*`, each
context's own `testkit/`, and integration tests.

Each context also exposes a peer of `api/` / `bootstrap/` / `internal/`
called `testkit/`: a coordinated test-fixture surface. testkit owns
the schema-applier wrappers (`ApplySchema`, `MigrateSchema`),
context-specific fakes/seeders, and (in detection's case) the
rule-replay harness used by cross-context catalog tests. The split
rule is:

- Production wiring: `cmd/main` calls `bootstrap`; `bootstrap` is for
  standing up real service instances.
- Tests: per-context unit tests, cross-context integration tests
  (including `server/testdb/full`'s composer), and rule fixture
  replays all reach for `testkit`. arch-go pins each testkit to its
  own context so cross-context test allowances cannot be exploited as
  transitive sneak-in paths to a third context.

The migration runs as seven phases, smallest blast radius first
(`identity` -> `endpoint` -> `rules` -> `response` -> `detection` ->
deletions -> arch-lint tightening). Each phase is one PR, ships
independently, and keeps the test suite green. Phase-by-phase
implementation tasks are tracked in the per-phase PRs and their commit
history rather than embedded in this ADR (an ADR captures the durable
decision; the file-by-file move list is operational and changes shape
as the migration proceeds).

## Consequences

**Good:**

- Clear ownership. Every table has exactly one context that writes to
  it. Every HTTP route lives in the context that owns its data. Every
  test lives in the context whose surface it exercises. `git blame` on
  any production line points to the right owner without guessing.
- Detection content becomes separable from the engine. `rules/api`
  exposes a `ContentService` interface; the engine consumes whatever
  set of rules the service returns. Migration to data-driven rule
  formats (YAML, Sigma, etc.) becomes a substitution of the catalog,
  not a redesign of the pipeline.
- The hot path stays a single optimisation unit. Inside `detection/`,
  the processor goroutine, graph builder, rule executor, and MySQL
  layer are all siblings. No interface hops, no type translations, no
  cross-context transactions in the inner loop.
- Compiler-enforced privacy. Go's `internal/` rule structurally
  prevents another context from importing implementation details. The
  arch-lint config is the small additional rule layer Go cannot
  express; the bulk of the dependency invariants are free.
- Test isolation falls out of the layout. Per-context integration
  tests in `internal/tests/` cannot reach into another context (the
  compiler refuses); cross-context tests in `test/integration/` can
  only reach context `bootstrap/` and `api/` packages (Go's `internal/`
  rule blocks the rest). The user's "per-context integration tests
  must not pull stuff from other contexts" requirement is enforced by
  the compiler, not by convention.
- Future split of `detection` into separate ingest / process /
  detect services becomes plausible without a redesign. Internal
  module boundaries inside `detection/` keep that path open.

**Bad:**

- Phase 5 (the `detection` move) is large: 1500-2500 lines of file
  moves in one PR. There is no smaller intermediate state that ships
  meaningful value without exposing partially-migrated tables.
- Rule signature changes from `Evaluate(ctx, events, *store.Store)` to
  `Evaluate(ctx, events, detection.GraphReader)`. The interface is
  narrower (three methods rules actually use today), so the change is
  mechanical, but every rule file changes in the same PR (phase 3).
- Rule definitions still live in the project as Go code. The boundary
  is set up for a later YAML migration, but contributors who expected
  rule changes to be content-only PRs will still need a Go build for
  now.
- Schema-bootstrap flow gets more moving parts. `cmd/main` calls each
  context's `bootstrap.ApplySchema` in a fixed order
  (`identity, endpoint, rules, response, detection`) instead of one
  monolithic `store.applySchema` block. FK ordering is enforced by
  call order, not by a single SQL script.
- One bug in `detection`'s mysql layer can blast-radius the entire
  hot pipeline. Mitigated by tighter test coverage there
  (Layer 2 + Layer 3) and by the fact that we already have this
  property today; the modular-monolith layout does not change it.

## Alternatives considered

**Strict per-table contexts (one per table, ~9 contexts).** Each table
gets its own context (`events`, `processes`, `hosts`, `alerts`,
`commands`, ...), each with `bootstrap/` + `api/` + `internal/`. Rejected
because it fragments the hot pipeline at the worst possible place: the
processor would need to call `events.api`, then `process.api`, then
`alert.api`, with type translations at each seam, every batch. Loses
single-transaction guarantees across `alerts` + `alert_events`. Loses
shared in-memory state (parent-PID lookups, recent-alert dedup, host
caches) that the current pipeline relies on. The fragmentation cost is
paid every batch on the EDR's most performance-sensitive path; the
modularity benefit is paid back only when a contributor wants to touch
one table without seeing the others, which is rare in this codebase.

**Keep the current layout, just shrink `store/`.** Move the events parts
into `ingest`, the process parts into `processor`, etc., but leave
everything else flat at `server/<package>/`. Mechanical, low-risk, no new
concepts. Rejected because it doesn't solve the central problem: there
is still no public-vs-internal boundary, no ownership statement, no
content-vs-engine separation. Future contributors still face a flat
2-dozen-package tree with implicit ownership. The benefit-to-cost ratio
of going further is favourable enough that we should do the larger move
now while the codebase is still small.

**Adopt only the directory layout, defer `internal/` enforcement until
later.** This was the original plan revision. Switched to using
`internal/` from day one because Go's `internal/` rule is free at any
nesting depth, costs nothing to adopt, and forecloses an entire class of
accidents the moment we adopt any modularity at all. Deferring it would
have meant a phase 7 cleanup that is now subsumed into the per-phase
moves.

**Use Fleet's custom `archtest` rather than a third-party tool.** Fleet
ships `server/archtest`, ~200-300 lines that walk `go list -deps` and
fail tests on disallowed imports. Honest in-tree, no dependency,
matches Fleet's pattern. Rejected because for five contexts the rule set
is small enough that `arch-go`'s declarative YAML is more readable than
imperative Go code, and `arch-go` is well maintained
(v2.1.2, Feb 2026). The "one more thing to maintain" cost is lower with
a third-party tool than with a vendored ~250 LOC checker.

**Use `go-arch-lint` instead of `arch-go`.** `go-arch-lint` has more
GitHub stars (469 vs 255) and a longer history, but is CLI-only with no
`go test` integration. `arch-go`'s programmatic API lets us run arch
checks as a regular Go test, so a violation breaks `go test ./...` in
the same way a unit-test failure does. Local feedback latency matters
more than star count.

**Use `depguard` (already in our `golangci-lint` config) for everything.**
`depguard` is great for block-list rules ("no `pkg/errors`") and we keep
it for those. It's awkward for "may only depend on" allow-list rules and
doesn't have a natural way to express "anything under
`server/detection/internal/**` may import only the platform list and
own-context paths." We use both: `depguard` for block-list deps,
`arch-go` for context boundaries.

**Keep all schema in one place, add `internal/` rules only to imports.**
Considered keeping `server/store/applySchema` as the single CREATE TABLE
function and giving each context only its query layer. Rejected because
the point of bounded contexts is exclusive write ownership of tables;
splitting reads from writes from DDL undermines that. If a context owns
its rows but cannot run its DDL, the ownership statement is
half-fictional.

## References

- Fleet's modular-monolith pattern documentation:
  https://github.com/fleetdm/fleet/blob/main/docs/Contributing/architecture/modular-monolith/README.md
- ADR 0001 (single Go module with `internal/`): the privacy mechanism
  this ADR extends one level deeper.
- arch-go: https://github.com/arch-go/arch-go (v2.1.2, Feb 2026).
- go-arch-lint (alternative considered):
  https://github.com/fe3dback/go-arch-lint.
- Migration plan with file-by-file moves and phase ordering:
  `claude/modular-monolith/plan.md` (gitignored scratch).
