# Architecture Decision Records

Architecture Decision Records (ADRs) capture the _why_ behind non-obvious architectural choices. The code shows _what_ is true today; ADRs preserve the context, constraints, and alternatives considered, so future maintainers (and future-you) don't reverse-engineer incorrect assumptions.

## When to write one

Write an ADR when a decision is:

- Hard or expensive to reverse ("which database", "one binary vs split", "which auth flow").
- Non-obvious from reading the code ("why ESF and not a kext", "why MySQL and not Postgres").
- Going to be questioned again in six months by someone who wasn't in the original discussion.
- A deliberate _non-decision_ (something common the project will not do, with rationale).

Do **not** write an ADR for a style nit, a local refactor, or a decision the code unambiguously documents.

## Format

Every ADR is a Markdown file named `NNNN-short-slug.md` where `NNNN` is the next available 4-digit number. Use the template at [`template.md`](template.md).

Each ADR is immutable after it lands. When a decision changes, write a _new_ ADR that supersedes the old one (mark the old file `Status: Superseded by NNNN` and link both directions). This gives you a trail of reasoning across time, not a single mutable "current view".

## Index

| ID | Title | Status |
| --- | --- | --- |
| [0001](0001-single-go-module-with-internal.md) | Single Go module with `internal/` for shared code | Accepted |
| [0002](0002-macos-apple-silicon-mvp-only.md) | MVP ships macOS on Apple Silicon only | Accepted |
| [0003](0003-standalone-product-not-fleet-integrated.md) | EDR is a standalone product, Fleet is a deployment channel | Accepted |
| [0004](0004-modular-monolith-bounded-contexts.md) | Modular monolith with bounded contexts | Implemented; amendment proposed in [0015](0015-clickhouse-visibility-store.md) (`visibility` context) |
| [0005](0005-mysql-only-data-plane.md) | MySQL is the only supported RDBMS for the data plane | Accepted; narrowing proposed in [0015](0015-clickhouse-visibility-store.md) |
| [0006](0006-otel-only-metrics.md) | OpenTelemetry is the only metrics pipeline; no Prometheus /metrics | Accepted |
| [0007](0007-xpc-peer-validation-libxpc-only.md) | XPC peer validation via libxpc code-signing requirement; no audit_token layer | Accepted |
| [0008](0008-selective-esf-subscription.md) | Selective Endpoint Security subscription; BTM for persistence, no broad NOTIFY_OPEN | Accepted |
| [0009](0009-migrations-via-goose.md) | Versioned, forward-only, per-context schema migrations via goose | Accepted |
| [0010](0010-stateless-server.md) | Stateless server: no in-process state survives a request | Accepted |
| [0011](0011-ha-architecture.md) | High-availability architecture: multi-replica app tier with rolling upgrade | Accepted |
| [0012](0012-capability-based-ui-gating.md) | Capability-based UI gating from a server-provided permission set | Accepted |
| [0013](0013-service-account-and-api-authentication.md) | Service-account and API authentication: client-credentials with short-lived self-validating tokens | Accepted |
| [0014](0014-inline-enforcement-failure-semantics.md) | Inline network enforcement: observation fails open, enforcement is explicit and resilient | Proposed |
| [0015](0015-clickhouse-visibility-store.md) | ClickHouse event store in a new `visibility` bounded context | Proposed |
| [0016](0016-event-delivery-substrate.md) | Event delivery: database-backed work queue now, streaming substrate at scale | Accepted |

## Tooling

No tooling. `cat docs/adr/*.md` is the viewer. The point of ADRs is that the write-up itself is the product, not the automation around it.
