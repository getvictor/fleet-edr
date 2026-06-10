# 0011. High-availability architecture: multi-replica app tier with rolling upgrade

- Status: Accepted
- Date: 2026-06-01
- Deciders: getvictor

## Context

The v0.1.0 availability commitment is that the EDR control plane stays up across routine operations - schema upgrades, replica restarts, binary cutovers - rather than requiring a maintenance window that takes the EDR offline. That goal drove a sequence of changes (the `add-server-availability` arc) whose individual decisions are recorded in their own ADRs and the `server-availability` spec. This ADR is the capstone: it records the overall topology those pieces add up to, so an operator or a future contributor has one place that explains how the parts fit rather than reconstructing it from five PRs.

The pieces, each load-bearing for the topology:

- **Versioned, forward-only, per-context migrations** applied at boot (ADR-0009). A rolling upgrade runs two binary versions against one database during the cutover, so schema changes must be expand-contract and the apply must tolerate concurrent boots.
- **A stateless application tier** (ADR-0010): no in-process state survives a request that a peer replica would need. This is what lets the load balancer route any request to any replica and lets a replica be drained and replaced mid-upgrade.
- **Graceful, load-balancer-drainable shutdown** on SIGTERM: the replica reports `/readyz` 503 for a bounded drain window so the LB removes it from rotation before the listener closes, then finishes in-flight requests.
- **Single-instance periodic work coordinated by a MySQL advisory lock** (the leader coordinator): event retention and the stale-process TTL reconciler run on exactly one replica and fail over when the holder exits or its connection drops.
- **Throughput-bound work that scales horizontally**: the event processor claims batches with `SELECT ... FOR UPDATE SKIP LOCKED`, so it runs on every replica without coordination, each claiming disjoint rows.
- **A shared MySQL data plane** (ADR-0005) holding all durable cross-request state: sessions, CSRF tokens, the event queue, alerts, application-control policy.

## Decision

Ship the server as a horizontally-scalable, stateless application tier of N identical replicas behind a load balancer, in front of one shared MySQL. The reference stack is `packaging/docker-compose-multi-replica.yml` (two replicas + MySQL + an NGINX or HAProxy proxy). The supported upgrade procedure is a rolling upgrade: replicas are replaced one at a time, the LB drains each via `/readyz`, and the first replica of the new version to boot applies any pending migrations under a boot-time advisory lock (the rest see an already-applied corpus and no-op). The control-plane availability target is 99.9%.

Three per-replica behaviours are accepted, bounded, and documented rather than centralised in v0.1.0:

- **Per-IP rate limiting counts per replica.** An attacker behind N replicas gets N times the per-replica budget. Operators size the per-replica limit accordingly; `docs/operations.md` documents the math.
- **The async audit-write queue can drop its in-memory backlog on a hard kill.** The synchronous audit path (writes, denies, auth events) is durable; only sampled read-audit events ride the async queue, which dual-emits to slog so the secondary sink retains them even when the in-flight queue is lost. `docs/operations.md` documents the trade-off.
- **MySQL is the remaining single point of failure.** v0.1.0 does not ship MySQL replication or read-routing; the customer brings a replicated or managed MySQL for a fully HA datastore. The 99.9% control-plane target is conditional on the customer's MySQL and load balancer being available.

Endpoint protection does not depend on control-plane availability: application-control enforcement runs in the system extension from a cached snapshot, and the agent buffers events in its local SQLite queue and uploads them when the server returns, so a control-plane outage delays alerting on the backlog rather than losing endpoint data (up to the queue cap).

## Consequences

- **Easier**: zero-downtime upgrades and replica restarts; horizontal scale is "add a replica"; no LB session affinity to configure; a crashed replica is replaced without customer-visible state loss.
- **Harder / the cost**: every schema change must be expand-contract (ADR-0009) because two versions read and write the same MySQL during a cutover; the stateless invariant (ADR-0010) is a standing review constraint on new in-process state; operators must run a real load balancer and, for a fully HA datastore, a replicated MySQL.
- **Accepted gaps**: per-replica rate-limit fragmentation, async-audit-queue loss on hard kill, and the MySQL SPOF are real but bounded; documented, not fixed, in v0.1.0. Each has a v0.1.x follow-up (shared rate limiter, audit outbox, MySQL replication) listed as out of scope here.

## Alternatives considered

**An external coordinator (etcd / Consul / ZooKeeper / Redis) for leader election and shared rate limiting.** Rejected for v0.1.0: it adds a second stateful dependency to operate and back up alongside MySQL, for a pilot-scale deployment (10-500 endpoints) where a MySQL advisory lock already provides exactly-one-replica coordination with no new moving parts. Revisit if the fleet outgrows a single MySQL.

**Kubernetes-native HA (Deployment + leader-election lease + HPA).** Rejected as the _reference_: it presumes a Kubernetes substrate many pilot customers do not run. The stateless design works on k8s unchanged (it is just another way to run N replicas behind a service), so this is a deployment choice left to the operator, not an architecture the product mandates.

**Sticky sessions at the load balancer** to allow per-replica in-memory session state. Rejected; see ADR-0010 (it breaks the moment a replica is drained, which is exactly what rolling upgrade does).

**Single replica with a fast restart (the v0.1.0 small-pilot variant).** Retained as a documented option for pilots that accept a brief maintenance window, but not the reference: a server restart or upgrade is a few seconds of 503, which is a maintenance window, not high availability.

## References

- ADR-0005 (`docs/adr/0005-mysql-only-data-plane.md`): MySQL as the only data plane, which the shared-store topology rests on
- ADR-0009 (`docs/adr/0009-migrations-via-goose.md`): the migration discipline a rolling upgrade requires
- ADR-0010 (`docs/adr/0010-stateless-server.md`): the stateless invariant this topology depends on
- `openspec/specs/server-availability/spec.md`: the requirements (migrations, drain, leader-coordinated periodic tasks, SKIP LOCKED processor scaling, cross-replica sessions/CSRF, rolling-upgrade-safe migrations) this ADR is the architecture record for
- `docs/operations.md`: the rolling-upgrade runbook and the rate-limiter / audit-queue accepted-gap decisions
- `docs/install-server.md`: the deployment topology, availability, and SLA documentation
- `ai/migrations/ha-architecture.md` and `ai/migrations/v0.1.0-execution-plan.md`: the design rationale and PR slicing for the arc
