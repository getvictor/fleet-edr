# 0010. Stateless server: no in-process state survives a request

- Status: Accepted
- Date: 2026-05-31
- Deciders: getvictor

## Context

The v0.1.0 availability commitment ships the server as a multi-replica application tier behind a load balancer, with rolling upgrade as the only supported upgrade procedure (see `ai/migrations/ha-architecture.md` and the `server-availability` spec). Two properties that topology depends on: any replica must be able to serve any request (the LB does not pin a client to a replica), and a replica must be able to restart - or be replaced during a rolling upgrade - without customer-visible state loss. Both properties break the moment a request's correctness depends on state that lives only in one replica's memory.

The codebase already mostly satisfies this: sessions and CSRF tokens are MySQL-backed (any replica validates a cookie minted by another), the event queue and detection state are in MySQL, and application-control snapshots are persisted. The risk is regression - a future change that reaches for an in-process map, channel, or cache to hold state that a peer replica would need.

## Decision

The server holds no in-process state that survives a request lifetime and that a peer replica would need to serve a subsequent request correctly. Concretely:

- **Durable, cross-request state lives in MySQL.** Sessions, CSRF tokens, alerts, the event queue, application-control policy - all shared via the store, never an in-memory authority.
- **Per-request state may ride in signed cookies** (e.g. the OIDC state/PKCE cookie). It is self-contained and verifiable by any replica.
- **Short-lived per-replica performance caches are permitted only when losing them on restart is harmless** - a read-through cache that re-populates from MySQL, not a write buffer that is the only copy of something. Such a cache must be documented as "per-replica perf cache, safe to lose" at its definition.

A few per-replica behaviours are accepted and documented rather than centralised in v0.1.0: the per-IP rate limiter counts per replica (an attacker gets N times the budget behind N replicas), and the async audit-write queue can drop its in-memory backlog on crash. Those are tracked in the operations docs and the `server-availability` arc; they are bounded, non-correctness-critical exceptions, not a licence for new in-process authority.

## Consequences

- **Easier**: a replica can be killed, restarted, or replaced mid-rolling-upgrade with no customer-visible state loss; the LB needs no session affinity; horizontal scale is "add a replica".
- **Harder / the cost**: code review now rejects a new in-process `map` / channel / queue that holds cross-request state without an explicit "this is a per-replica perf cache, safe to lose" justification. The reviewer (and Copilot, per the repo instructions) treats an undocumented in-memory store of shared state as a defect, not a performance win. The reviewer guidance is codified in `CLAUDE.md`.
- **Accepted gaps**: per-replica rate-limit fragmentation and async-audit-queue loss are real but bounded; documented, not fixed, in v0.1.0.

## Alternatives considered

**Sticky sessions (LB session affinity).** Let the LB pin a client to a replica so in-memory per-session state is safe. Rejected: it couples the LB configuration to application internals, breaks the moment a replica is drained (the pinned client's state is gone), and is exactly the fragility rolling upgrade must avoid. MySQL-backed sessions make affinity unnecessary.

**In-memory session / cache store (e.g. a process-local LRU as the authority).** Faster reads, no DB round-trip. Rejected as the authority for shared state: it is invisible to peer replicas and lost on restart, which violates both properties above. The read-through-cache variant (MySQL remains the authority) is permitted under the Decision.

**Defer statelessness to a later release.** Rejected: retrofitting statelessness after in-process state has accreted is far more expensive than holding the invariant from the start, and the HA topology ships in v0.1.0, not later.

## References

- `ai/migrations/ha-architecture.md` and `ai/migrations/v0.1.0-execution-plan.md`: the HA arc this invariant underpins
- `openspec/specs/server-availability/spec.md`: the requirement "The server holds no in-process state that survives a request lifetime" that this ADR is the enforcement artifact for
- ADR-0009 (`docs/adr/0009-migrations-via-goose.md`): the migration discipline the same rolling-upgrade topology requires
- `docs/operations.md`: the per-IP rate-limiter and audit-queue accepted-gap decisions (added with the HA arc)
