# Architecture maturity: what's enforced, by whom, and what's not

This doc is a companion to `docs/adr/0004-modular-monolith-bounded-contexts.md`.
It exists so a reader landing in this repo six months from now - or
someone deciding whether to invest in a new architectural pattern -
can answer two questions in one place:

1. Which architectural rules are enforced automatically, and which are
   on code-reviewer trust?
2. When should we invest in the next tier of patterns (ACL packages,
   event-driven cross-context calls, database-per-context, etc.)?

## What is enforced

### By the Go compiler (`internal/` rule)

Strongest tier. Bypassing this requires either editing Go itself or
arranging the package tree differently - neither is plausible.

- Each bounded context's `<X>/internal/` is invisible to anything
  outside `<X>/`. Other contexts cannot import
  `server/<X>/internal/anything` even if they wanted to. The compiler
  refuses at `go build` time.
- The repo-level `internal/` (e.g. `internal/observability`) is
  visible to any package under `github.com/fleetdm/edr/`, which is
  the entire repo, so it functions as "shared module-private" - not
  a bounded-context restriction.

### By arch-go (`arch-go.yml`, gated on every PR)

Encoded as declarative rules, run as a hard-fail CI check
(`.github/workflows/arch-go.yml`) and via `task lint:arch` locally
(also wired into the lefthook pre-push chain). arch-go inspects
**direct** imports only - see "Honest gaps" for the implications.

Today's rule families:

1. **Per-context `internal/` allow-list.** Each `<X>/internal/**` may
   only depend on its own context's packages, platform packages, and
   a narrowly-named set of cross-context allowances:
   - `**.<Y>.api` (the public types + interface contract)
   - `**.<Y>.testkit` (the test fixture surface; lets cross-context
     tests stand up `<Y>` without touching `<Y>/internal/`)
   - Specific platform packages (`attrkeys`, `httpserver`, `sqlhelpers`,
     `testdb`).
2. **Per-testkit Go-leaf rule.** Each `<X>/testkit` package is pinned
   to its own context plus platform. This prevents cross-context test
   allowances from being exploited as transitive paths to a third
   context: rules.internal is allowed to import detection.testkit, but
   detection.testkit cannot pull in identity / endpoint / response.
3. **api-purity.** Each `<X>/api` may only depend on its own
   sub-packages plus platform; one explicit exception is
   `rules.api → detection.api` for the type-alias re-export the
   catalog rule files rely on. Catches accidents like "rules.api
   gained a helper that imports detection/internal/mysql for
   convenience" before they ship.
4. **Platform isolation.** `server/{config, bootstrap, httpserver,
   logging, metrics, attrkeys, apidocs, sqlhelpers, ui}` may not
   import any bounded context. (`server/testdb` is the noted
   exception - its sub-package `testdb/full` legitimately imports
   each context's testkit; arch-go's prefix-based pattern matching
   can't cleanly separate the two, so the leaf invariant lives in
   code review.)

### By the test pyramid (`//go:build integration`)

Test layers map onto explicit file locations and build tags:

- **Layer 1 - unit.** Co-located with code at `<X>/internal/<module>/`.
  Default tag, runs on every `go test ./...`. May use `testdb.Open` +
  `<X>/testkit.ApplySchema` for DB-touching tests; skips cleanly when
  `EDR_TEST_DSN` is unset.
- **Layer 2 - per-context integration.** Lives at
  `<X>/internal/tests/`, package `tests`, build-tag `integration`.
  Exercises one bounded context end-to-end through its public
  `bootstrap.New` + service surface.
- **Layer 3 - cross-context integration.** Lives at
  `test/integration/`, package `integration`, build-tag
  `integration`. The canonical fixture in `test/integration/setup.go`
  composes every context the way `cmd/main` does; the canonical
  end-to-end smoke (`full_path_test.go`) runs the agent-enroll →
  ingest → admin-command → agent-ack flow.

Layers 2 and 3 stay out of the default `go test ./...` invocation
(developer-edit cycle stays fast); CI's `test:go:server:coverage`
target runs with `-tags=integration` so all layers contribute to
the SonarCloud coverage attribution.

## What is NOT enforced (code review only)

The list of trust-only invariants. Each is small enough that review
catches violations reliably; encoding them would require either
custom tooling or arch-go capabilities the project doesn't ship.

- **No transaction crosses a bounded-context boundary.** Each
  `<X>/internal/mysql/` writes only to `<X>`'s own tables. A
  cross-context flow ("enroll seeds initial commands") is an ordered
  sequence of idempotent operations, not one transaction. There is
  no automated check; arch-go can't see SQL transactions, only
  imports. Review heuristic: any function on a `Service` that calls
  another context's `Service` and also calls its own `mysql.Store`
  inside a single `BeginTx` is a smell.
- **`<X>/testkit` is for tests, not for production code.** arch-go's
  v1.7 rule families don't include "shouldOnlyBeAccessedBy", so the
  invariant lives as a comment in `arch-go.yml` plus the natural
  fact that testkit functions take `*testing.T` parameters and
  surface test-only types (Scenario, FixtureCase). A new package
  that imported testkit in production would be a code-review smell
  that's easy to spot.
- **Platform's `server/testdb` may not import a context.** The leaf
  package is clean today; arch-go's prefix-match catches the
  sub-package `testdb/full` which legitimately imports each testkit.
  Review heuristic: any new import in `server/testdb/open.go` (the
  leaf) that targets a `server/<X>/` path is the violation.
- **No cross-context FKs.** The migration dropped the only one
  (`fk_alerts_updated_by`) and replaced it with the
  `identity.api.UserExists` code-level check. Schema review on every
  DDL change is the gate; arch-go doesn't see DDL.
- **Wire format (`schema/events.json`) is the contract between two
  codebases (Swift extension, Go server) plus the Go agent that
  shuttles bytes between them.** Changes to it require coordinated PR
  work. Review heuristic: any change to `schema/events.json` that
  doesn't include corresponding changes in `server/detection/api/wire/`
  (server-side decode/encode) and the Swift extension's event
  serializer is incomplete. The agent itself stores events as opaque
  `json.RawMessage` in its SQLite queue and re-emits them verbatim, so
  it generally doesn't need a wire/ package of its own - but new
  fields the agent has to read (`agent_version`, `host_id`) still
  require an `agent/uploader` change.
- **`bootstrap` is for production wiring.** Production importers of
  `<X>/bootstrap` are `cmd/fleet-edr-{server,ingest}` and
  `<X>/testkit`. Tests at `<X>/internal/tests/` and
  `test/integration/` import bootstrap legitimately for service
  composition; arch-go doesn't see test-file imports, so a stray
  production import of bootstrap from a non-listed package is a
  review smell. The fact that the only realistic vector is "someone
  introduces a brand-new package outside cmd/ that wires services"
  makes this very low risk.

## Comparison to industry practice

**Aligned with the modular-monolith canon (Shopify Packwerk-shaped,
Backstage Plugin Architecture, ThoughtWorks Tech Radar 2024 entry on
Modular Monoliths):**

- Bounded contexts at the package level - ✓.
- Public-API / private-internal split with compiler-level
  enforcement - ✓ (Go's `internal/`).
- Per-context schema ownership; no cross-context FKs - ✓.
- Architecture lint encoded as code, run as a blocking CI check -
  ✓ (`arch-go`).
- Single-process, single-DB hot path; cross-context calls go through
  narrow interfaces with no allocation in the inner loop - ✓
  (`detection.api.GraphReader` is the canonical example).
- Three-layer test pyramid - ✓ (unit + per-context + cross-context).

**Stronger than the Fleet (`fleetdm/fleet`) reference the strategic
plan cites:**

- Explicit bounded contexts vs. Fleet's layered datastore +
  service + handler shape. Both are valid; ours scales better as the
  rule catalog grows because rules + detection + response are
  separated from each other rather than all sharing one `service`
  package.
- `<X>/api/` + `<X>/bootstrap/` + `<X>/internal/` + `<X>/testkit/`
  peer subpackages, each with a distinct purpose, vs. Fleet's
  mixed-concerns packages.
- Declarative `arch-go.yml` vs. Fleet's bespoke `archtest` (~200
  LOC of Go). Both work; ours has fewer maintenance hands.
- A coordinated `<X>/testkit` test surface vs. Fleet's per-package
  test helpers that drift with their callers.

**What we deliberately don't do (yet):**

- **No Anti-Corruption Layer (ACL) packages.** Cross-context value
  types are simple. ACL packages translate type-shapes between
  contexts when they diverge; today rules.api re-exports detection.api
  types directly (and re-export is documented as an explicit alias).
  When a future change requires rules to model `Event` differently
  than detection - e.g. adding a `RuleHints` field that detection
  doesn't care about - the right move is an ACL package
  (`server/rules/internal/eventacl/`) that converts between shapes.
- **No event-driven cross-context communication (Kafka / NATS /
  Watermill).** All cross-context calls today are direct interface
  invocations. This is fine and faster for a single-process monolith;
  switching to events would be an architectural choice driven by
  multi-process scale-out, not by isolation needs.
- **No database-per-context.** All five contexts share one MySQL
  instance, partitioned by table ownership. Fleet, GitLab,
  GitHub-the-monolith all do the same; database-per-service is a
  microservices decision.

## Graduation criteria

When to invest in the next tier of architectural patterns. The
criteria are scale + pain signals, not calendar dates. Fix the
problem when it bites; not before.

### When to introduce ACL packages

**Trigger:** a context's api/ types start growing fields that are
meaningful only to one consumer, OR another context's tests start
importing types via aliases that don't quite fit (e.g. needing a
subset of fields).

**Today:** rules.api re-exports detection.api `Event`, `Process`,
`Finding`, `GraphReader`, `TimeRange`, `NullRawJSON` as
type-aliases. The aliases are documented as a concession in
`arch-go.yml` §api-purity. As long as the types are 100% the same
shape, alias-style re-export is correct.

**Migration if triggered:** add `<X>/internal/<Y>acl/` (e.g.
`rules/internal/detectionacl/`) with `func ToRuleEvent(e
detectionapi.Event) RuleEvent`. Update rule signatures to take the
ACL-shaped type. Drop the alias entry in arch-go.yml.

### When to introduce event-driven cross-context calls

**Trigger:** a cross-context interface call becomes the bottleneck
(detection's processor blocks on response.Insert; OR rules'
fan-out blocks on endpoint.ActiveHostIDs), AND the workload would
naturally fan out - multiple ingest workers, async fan-out at
enroll time.

**Today:** every cross-context call is a direct method invocation
in the same process. Latency is sub-microsecond; not a bottleneck.

**Migration if triggered:** introduce a small in-process queue
(`server/<X>/internal/queue/`) backed by a buffered channel. Move
the cross-context call onto a background goroutine reading from
the queue. If the workload eventually wants to span multiple
processes, swap the in-process queue for Kafka / NATS without
changing the calling-context API.

### When to introduce database-per-context

**Trigger:** schema for one context grows to a size where shared-DB
locking, vacuuming, or backup windows are visible problems, OR a
context needs storage characteristics MySQL doesn't offer (full-text
search → Elasticsearch; time-series → ClickHouse; graph queries →
Neo4j).

**Today:** ~50 GB target DB size at MVP scale (10-500 endpoints
× retention days × event rate). MySQL handles that single-instance
without strain.

**Migration if triggered:** the bounded-context split already
isolates which tables move. The change is `<X>/internal/mysql/`
becomes `<X>/internal/<store-impl>/` (e.g. `<X>/internal/clickhouse/`)
behind an unchanged `<X>/api.Service` interface. cmd/main wires the
new client; nothing else changes. This is the architecture's biggest
payoff.

### When to split into separate processes / services

**Trigger:** context lifecycles diverge enough that a single
deployment unit is the bottleneck - e.g. detection rule reload
requires a server restart that drops in-flight ingest, OR ingest
QPS demands horizontal scaling that the operator API can't usefully
share.

**Today:** `cmd/fleet-edr-server` (full surface) and
`cmd/fleet-edr-ingest` (intake-only) already split for that reason.
Both share one MySQL.

**Migration if triggered:** introduce a third binary,
`cmd/fleet-edr-{operator|response|rules}` per the new boundary.
The bounded-context split makes this primarily a wiring change in
cmd/, not a restructure of `server/`. The remaining work is
authentication between processes (mTLS or token-keyed API).

## Maintenance

- This doc is referenced from `docs/adr/0004-modular-monolith-bounded-contexts.md`
  as the "what's enforced + when to graduate" companion. Update it
  when:
  - A new arch-go rule family lands.
  - A graduation criterion fires (and the response is to invest).
  - Industry practice shifts the comparison points (e.g. Fleet
    refactors away from the layered datastore-service shape).
