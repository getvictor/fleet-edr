# Server Availability Specification

## Purpose

Server availability is the set of invariants that let the Fleet EDR control plane stay up across routine operations (schema upgrades, replica restarts, and rolling binary cutovers) without requiring a maintenance window that takes the EDR offline. It is the server-side half of the v0.1.0 availability commitment: the application tier is stateless and horizontally scalable, a load balancer can drain a replica cleanly, periodic work runs on exactly one replica, first boot is safe under concurrent replica start, and the schema is managed by versioned migrations that a rolling upgrade tolerates.

This spec defines the behavior the deployment topology and the operator runbook depend on. The migration discipline below is load-bearing for the rest: rolling upgrade means two binary versions read and write the same MySQL during a cutover, so the schema corpus and the way it is applied must admit both. The migration decision and its rationale are in [`0009-migrations-via-goose.md`](../../../docs/adr/0009-migrations-via-goose.md); the rolling-upgrade and multi-replica shape is in [`0011-ha-architecture.md`](../../../docs/adr/0011-ha-architecture.md).

## Requirements

### Requirement: Schema is managed by versioned forward-only per-context migrations

The system SHALL apply database schema through versioned, forward-only migration files applied at boot rather than by re-running idempotent DDL in process. A bounded context whose schema is managed this way owns an ordered migration corpus and a dedicated tracking table recording applied versions, so already-applied migrations are never re-run. Applying such a corpus SHALL be idempotent: a boot whose corpus carries no new migration relative to the tracking table MUST make no schema change and MUST succeed. Migrations SHALL be forward-only; the system MUST NOT depend on down-migrations for recovery (the documented rollback path is restore-from-backup).

Every bounded context that owns database tables is managed this way. That is stated as a property rather than as a list of contexts, because a hand-maintained list drifts silently: the previous enumeration named five contexts and had fallen three behind the tree.

The standalone migration tool SHALL apply the relational corpus of every such context. A context it omits is not merely unmigrated: the tool reports success having skipped it, so a deployment that migrates as a privileged step and then runs without schema-change permission fails at boot on that context alone, and a multi-replica boot races to apply it, which is the race a separate tool exists to remove.

The scope is the RELATIONAL corpus, and the limit is stated rather than implied. One context keeps a separate corpus for the columnar event store, which the server applies at boot because the tool takes a relational connection only. A requirement covering that corpus would demand the tool apply something it cannot reach.

Whether a context is registered with that tool SHALL be checkable from the source tree rather than asserted against a maintained list, because a list of expectations drifts in step with the list it checks.

#### Scenario: Applying a baseline on a fresh database creates its tables

- **GIVEN** a fresh database with no migration tracking table
- **WHEN** the system applies a context's migration corpus
- **THEN** the tables defined by the corpus exist
- **AND** the context's tracking table records the applied version

#### Scenario: Re-applying an already-applied corpus makes no changes

- **GIVEN** a database whose tracking table already records every migration in a context's corpus
- **WHEN** the system applies that corpus again
- **THEN** the apply succeeds without error
- **AND** no migration is re-run and the schema is unchanged

#### Scenario: A context shipping migrations is registered

- **GIVEN** a bounded context in the source tree that ships relational migration files
- **WHEN** the registered contexts are compared against the tree
- **THEN** that context is registered with the standalone migration tool

#### Scenario: A registered context ships migrations

- **GIVEN** a context registered with the standalone migration tool
- **WHEN** the registered contexts are compared against the tree
- **THEN** it ships relational migration files, so its registration is not a step that silently does nothing

### Requirement: The server holds no in-process state that survives a request lifetime

The server SHALL NOT retain in-process state that outlives a single request and that a peer replica would need to serve a subsequent request correctly. Durable state SHALL live in the shared MySQL store; per-request state MAY ride in signed cookies; short-lived per-replica performance caches are permitted only when losing them on a restart is harmless. This invariant is what lets any replica behind the load balancer serve any request and lets a replica restart without customer-visible state loss. It is enforced at review time against `docs/adr/0010-stateless-server.md`. The invariant is observable end to end: state written by one replica must be servable by any other replica through the shared store.

A single sanctioned exception is the agent control-connection gateway. The gateway's only in-process state is, per connection: the live socket (keyed by host), the connection's authentication metadata (token epoch and expiry, so it can be re-checked against the revocation snapshot without a database lookup), and the set of in-flight command identifiers. It persists nothing durable: all command state remains in the shared MySQL store. The loss of a gateway or any of its connections SHALL force the affected agents to reconnect (and to fall back to the polled command path meanwhile) with no command loss, because the command rows and their statuses live in the shared store. This is a named, bounded stateful tier, not a license for request-surviving authority elsewhere.

#### Scenario: State written on one replica is served by another

- **GIVEN** durable state was written to the shared MySQL store by a request handled on one replica
- **WHEN** a later request that depends on that state is routed to a different replica
- **THEN** the second replica serves it correctly from the shared store, with no reliance on any request-surviving in-process state from the first replica

#### Scenario: Losing the gateway forces reconnect without command loss

- **GIVEN** a host holding a control connection on a gateway that then stops
- **WHEN** the gateway and its connections are lost
- **THEN** the host reconnects (to the same or another replica) and meanwhile falls back to the polled command path
- **AND** no queued command is lost, because command state was never held only in the gateway's memory

### Requirement: TLS may be terminated by a front proxy

The server SHALL terminate TLS itself by default and refuse to boot without a certificate and key (issue #140 removed the unguarded plaintext-HTTP mode). It SHALL additionally support running behind a TLS-terminating proxy (a PaaS edge, ALB, or reverse proxy) via an explicit opt-in: when the operator sets that opt-in, the server SHALL listen plaintext HTTP and SHALL NOT require certificate files, on the assertion that the proxy terminates TLS in front of it. The opt-in and server-terminated TLS SHALL be mutually exclusive so the operator cannot ambiguously configure both. When running in proxy-terminated mode the server SHALL emit a startup warning that it is serving plaintext and must not be exposed directly.

#### Scenario: Proxy-termination opt-in allows plaintext HTTP

- **GIVEN** an operator who sets the proxy-termination opt-in and supplies no certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration succeeds and the server listens plaintext HTTP rather than refusing to boot

#### Scenario: Proxy flag and cert files are mutually exclusive

- **GIVEN** an operator who sets the proxy-termination opt-in AND supplies certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration fails with an error that the two are mutually exclusive

#### Scenario: Mandatory TLS remains the default

- **GIVEN** an operator who sets neither the proxy-termination opt-in nor certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration fails because a certificate and key are required

### Requirement: SIGTERM produces a load-balancer-drainable graceful shutdown

On SIGTERM the server SHALL begin draining before it closes its listener: it SHALL report not-ready on its readiness probe so a load balancer removes the replica from rotation, SHALL keep serving in-flight and newly-accepted requests for a bounded drain window, and SHALL then stop accepting new connections and wait for in-flight requests to finish up to a bounded shutdown deadline. The process SHALL exit within the drain window plus the shutdown deadline. The drain window is operator-configurable and MAY be zero to disable the wait.

#### Scenario: Readiness reports not-ready once draining begins

- **GIVEN** a running server whose readiness probe reports ready
- **WHEN** the server begins draining on SIGTERM
- **THEN** the readiness probe reports not-ready with HTTP 503
- **AND** it does so regardless of whether the database check would otherwise pass

#### Scenario: In-flight requests complete before the listener closes

- **GIVEN** a server draining on SIGTERM with a request in flight
- **WHEN** the drain window elapses and graceful shutdown runs
- **THEN** the in-flight request completes successfully before the process exits

#### Scenario: The process exits within the drain plus shutdown deadline

- **GIVEN** a server draining on SIGTERM
- **WHEN** the drain window and the shutdown grace deadline elapse
- **THEN** the process has exited

### Requirement: First-boot admin seed is safe under concurrent replica boot

When multiple replicas boot concurrently against a fresh database, the first-boot break-glass admin seed SHALL produce exactly one admin row and every replica's seed SHALL succeed. The replica that loses the create race SHALL adopt the existing row rather than failing its boot. The break-glass redemption banner SHALL be emitted by at most one replica per concurrent boot, so an operator sees a single redemption URL rather than one per replica.

#### Scenario: Two replicas seeding concurrently produce exactly one admin row

- **GIVEN** a fresh database and two replicas running the admin seed concurrently
- **WHEN** both seed attempts run
- **THEN** both succeed
- **AND** exactly one break-glass admin row exists

#### Scenario: Only one replica emits the bootstrap-token banner under concurrent boot

- **GIVEN** multiple replicas booting concurrently with the admin not yet redeemed
- **WHEN** they race to emit the break-glass redemption banner under the leader gate
- **THEN** exactly one replica emits the token and prints the banner
- **AND** the other replicas do not

### Requirement: Replica identity is observable via service.instance.id

Every replica SHALL attach a `service.instance.id` resource attribute to the telemetry it emits so an operator can tell replicas apart in the observability backend. The identifier SHALL be stable for the lifetime of the process.

#### Scenario: Every emitted span carries the service instance id

- **GIVEN** a configured telemetry resource for a replica with a service instance id set
- **WHEN** the resource is built
- **THEN** it carries a non-empty `service.instance.id` attribute

#### Scenario: The service instance id is stable for the process lifetime

- **GIVEN** a running replica
- **WHEN** its service instance id is read more than once
- **THEN** the same value is returned each time

### Requirement: Periodic tasks run on exactly one replica via MySQL advisory locking

The system SHALL run its single-instance periodic maintenance tasks (event retention and the stale-process TTL reconciler) on exactly one replica at a time, coordinated through MySQL named advisory locks, even though every replica runs the same binary. A replica that does not hold a task's lock SHALL NOT run that task, and SHALL take over when the current holder releases the lock or its connection drops. The event processor is explicitly NOT coordinated this way: it scales across replicas via row-level SKIP LOCKED claiming, so each replica processes disjoint batches.

#### Scenario: Single replica acquires the lease uncontended

- **GIVEN** a single replica and no other holder of a task's lock
- **WHEN** the replica runs the task under the coordinator
- **THEN** it acquires the lock and runs the task

#### Scenario: Concurrent replicas elect exactly one leader per task

- **GIVEN** two replicas contending for the same task lock
- **WHEN** both run the task under the coordinator
- **THEN** exactly one replica acquires the lock and runs the task
- **AND** the other does not run the task while the holder keeps the lock

#### Scenario: Lease releases on context cancel

- **GIVEN** a replica holding a task lock
- **WHEN** its context is cancelled for a graceful shutdown
- **THEN** it releases the lock
- **AND** a waiting replica acquires it

#### Scenario: Lease releases on replica crash via connection close

- **GIVEN** a replica holding a task lock
- **WHEN** its database connection drops because the process crashed
- **THEN** MySQL releases the lock
- **AND** another replica can acquire it

### Requirement: The processor scales across replicas via SKIP LOCKED

The system SHALL claim event batches for processing with row-level `SELECT ... FOR UPDATE SKIP LOCKED` so the event processor runs concurrently both across every replica and across multiple worker goroutines within a single replica, each claimer receiving a disjoint set of unprocessed events, and no event row claimed by more than one claimer at a time. This is the deliberate counterpart to the leader-gated periodic tasks: throughput-bound event processing scales horizontally across the replica fleet and vertically across the cores of one replica, rather than running on a single elected replica or a single goroutine. The intra-replica worker count is a fixed compiled constant, not an operator knob, and the in-process workers share one process-graph builder and one detection engine so cross-batch builder state stays coherent.

A claim SHALL be scoped to a single host, returning that host's claimable events in timestamp order. Disjointness alone is not sufficient for the process-graph builder: it resolves each `exec` against the rows already flushed, so an `exec` folded while its `fork` is still unflushed in another claimer's batch is indistinguishable from an `exec` with no `fork`, and the builder materializes a duplicate generation with a fabricated fork time and no back-reference to the image it replaced. The system SHALL therefore serialize the processing of one host's events, so that at most one claimer at a time is claiming, folding, and flushing for a given host, while different hosts continue to be processed in parallel. Serialization SHALL be coordinated through the same MySQL advisory locking the periodic tasks use, so it holds across replicas and releases automatically when a holder's connection drops. A claimer that finds a host already held SHALL proceed to another host with pending work rather than waiting on it.

The serialized region SHALL cover claiming, folding, and flushing, and SHALL NOT extend over rule evaluation, which only reads the materialized graph. A batch whose folding failed SHALL be returned to the queue before the host's serialization is released, so the next claimer cannot take that host's later events and fold them ahead of the events being retried.

Every queue transition that follows evaluation, both the acknowledgement of a processed batch and the requeue of one that failed evaluation, SHALL also be serialized against that host's claimers. The statements performing them take row locks as they scan, so an earlier event of a batch can be locked while a later one is not, and a claimer arriving in that window skips the locked row and takes the later one, folding it without its predecessor. The in-flight bound does not cover this: it counts only claims that are still live, and the window is reached precisely when the claim has outlived its lease. This serialization SHALL be a separate window rather than an extension of the claim's, so that rule evaluation still runs outside it and a slow rule cannot hold a host.

A claim SHALL NOT reach past an event that another claimer still holds. An in-flight event is invisible to the claimable predicate rather than blocking it, so without this bound a claimer that died between claiming a `fork` and flushing it would leave a hole the following `exec` pours through, reintroducing the exec-with-no-fork fold that scoping the claim to one host exists to prevent. When a host has an unexpired in-flight event, the system SHALL offer only that host's events strictly older than the oldest in-flight one, and SHALL offer nothing for that host when none are older. A host may therefore have no claimable work until an abandoned claim's lease expires, which is bounded by the lease and is preferable to folding its stream out of order. Claimers SHALL NOT reclaim another claimer's unexpired in-flight events. Queue timestamps originate in agent payloads, so the bound SHALL hold for any timestamp value an agent can send: no timestamp SHALL be reserved as a sentinel, since a reserved value either strands an event stamped with it or, through arithmetic on it, silently removes the bound.

Because a claimer inside that region occupies two database connections at once, the connection the advisory lock pins and the connection its claim and flush use, the system SHALL size its worker count to the connection pool so that the workers cannot exhaust it: exceeding the pool does not degrade throughput gracefully but stalls the pipeline with every worker holding a lock connection while waiting for a claim connection. The pool is process-wide and shared with the request path and the background sweeps, so the workers SHALL be sized to a share of it rather than to all of it. A pool too small to serve even one worker SHALL be refused at startup, naming the pool size the deployment needs, because a single worker there would pin the only connection for its lock and then wait forever for a claim connection: that is the stall the sizing exists to prevent, and a deployment that refuses to boot states its problem where one that boots and silently processes nothing does not.

When no advisory-lock coordinator is available the system SHALL run a single worker and SHALL report that its per-host ordering then holds only within that replica. One worker per replica is not host serialization: another replica's worker can claim the same host concurrently, so the guarantee is available only where a coordinator is configured. The coordinator-less mode is for single-replica and test deployments.

#### Scenario: An acknowledgement holds the host lock

- **GIVEN** a batch that has been evaluated and is ready to be acknowledged
- **WHEN** the acknowledgement runs
- **THEN** it holds that host's serialization while it runs, so a concurrent claimer cannot skip an event it has locked and fold a later one first

#### Scenario: Two replicas claim disjoint event batches

- **GIVEN** unprocessed events in the shared store and two replicas claiming batches concurrently
- **WHEN** both run the SKIP LOCKED claim
- **THEN** each replica receives a batch of events
- **AND** no event appears in both replicas' batches

#### Scenario: Concurrent workers within one replica claim disjoint event batches

- **GIVEN** unprocessed events in the shared store and multiple processor workers in one replica claiming batches concurrently
- **WHEN** the workers run the SKIP LOCKED claim
- **THEN** each worker receives a disjoint batch and no event is claimed by more than one worker
- **AND** the materialized process forest is the same as if the events had been claimed by a single worker

#### Scenario: Events for one host are folded in causal order under concurrency

- **GIVEN** one host's queued stream in which several pids each fork, exec, re-exec, and exit
- **AND** several processor workers claiming concurrently with a batch size small enough that each event is claimed separately
- **WHEN** the workers drain the queue
- **THEN** the materialized forest is identical to the forest a single worker produces from the same stream
- **AND** each generation is materialized once, with the fork time the fork event reported rather than its own exec timestamp
- **AND** each re-exec references the generation it replaced, and that generation is closed

#### Scenario: A claim never spans hosts

- **GIVEN** queued events for two hosts
- **WHEN** a claimer claims for one of them
- **THEN** it receives only that host's events, in timestamp order
- **AND** a claim for the other host is disjoint from the first

#### Scenario: Serializing one host does not stall the others

- **GIVEN** queued events for two hosts and several processor workers
- **AND** one worker parked inside its claim-fold-flush region for the first host
- **WHEN** the remaining workers continue claiming
- **THEN** the second host's events are materialized to completion while the first host is still held
- **AND** the first host's events are materialized once the holder proceeds

#### Scenario: Worker count is bounded by the connection pool

- **GIVEN** a configured worker count that would need more database connections than its share of the pool allows
- **WHEN** the processor starts
- **THEN** it runs a reduced number of workers that the pool can serve
- **AND** it reports the reduction so the operator can see that the configured count was not honored

#### Scenario: A pool too small for one worker is refused at startup

- **GIVEN** a connection pool smaller than the connections one serialized worker holds
- **WHEN** the processor is constructed with an advisory-lock coordinator
- **THEN** construction fails rather than starting a worker that would stall on the pool
- **AND** the failure names the pool size the deployment needs

#### Scenario: A failed batch is requeued before the host is released

- **GIVEN** a claimed batch whose folding fails
- **WHEN** the claimer handles the failure
- **THEN** the batch is returned to the queue before the host's serialization is released
- **AND** the batch is not acknowledged

#### Scenario: A claim stops at a host's oldest in-flight event

- **GIVEN** a host whose oldest queued event is held by another claimer under an unexpired claim
- **AND** later events queued for that same host
- **WHEN** a claimer claims for that host
- **THEN** it receives no events for that host rather than the later ones
- **AND** once the abandoned claim's lease expires, that host's events are offered again in timestamp order starting from the oldest

#### Scenario: A claim bound cannot be defeated by an extreme timestamp

- **GIVEN** a queued event whose timestamp is the maximum representable value
- **WHEN** its host is claimed
- **THEN** that event is offered like any other, rather than being permanently unclaimable
- **GIVEN** instead a host whose oldest in-flight event carries the minimum representable timestamp
- **WHEN** that host is claimed again while the claim is unexpired
- **THEN** nothing is offered for it, because no event is strictly older, and the bound is not removed by arithmetic on that value

#### Scenario: A blocked host does not occupy a candidate slot

- **GIVEN** a host whose only unclaimed events sit behind an unexpired in-flight event, so every claim for it returns empty
- **AND** another host with events a claim would return
- **WHEN** the processor asks for candidate hosts and the blocked host would sort first as the longest-waiting
- **THEN** the blocked host is not offered as a candidate, and the host with claimable work is
- **AND** a candidate window filled with such hosts cannot hide the rest of the fleet for the length of a claim lease

### Requirement: Sessions and CSRF tokens validate across any replica

A user session and its CSRF token SHALL validate on any replica, not only the one that minted them, because session state lives in the shared MySQL store rather than in replica memory. A request bearing a valid session cookie SHALL be authenticated on a replica that did not mint the session, and an unsafe request bearing the session's CSRF token SHALL pass CSRF validation on that replica. This is what lets the load balancer route a user's requests to any replica without sticky sessions.

#### Scenario: Session minted on replica A validates on replica B

- **GIVEN** a session minted against the shared store
- **WHEN** a request bearing its cookie reaches a replica that did not mint it
- **THEN** that replica authenticates the request from the shared store
- **AND** an equivalent request carrying no session cookie is rejected

#### Scenario: CSRF token from replica A passes on replica B

- **GIVEN** a session and its CSRF token minted against the shared store
- **WHEN** an unsafe request bearing that CSRF token reaches a replica that did not mint it
- **THEN** that replica accepts the CSRF token
- **AND** an equivalent unsafe request carrying no CSRF token is rejected

### Requirement: Schema migrations are safe under rolling upgrade

When several replicas boot concurrently against one database during a rolling upgrade, the system SHALL apply schema migrations under a database advisory lock so no two replicas run the migration tool against the same database at once. Every replica SHALL still complete its boot-time apply: the per-context tracking table makes an already-applied corpus a no-op, so a replica that acquires the lock after another has already applied performs no schema change and boots successfully.

#### Scenario: Goose tracking table lock prevents concurrent apply

- **GIVEN** several replicas booting concurrently and racing to apply the same migration corpus
- **WHEN** they apply under the boot-time migration advisory lock
- **THEN** the applies are serialized so no two run at once
- **AND** every replica completes its apply and boots successfully

### Requirement: The default getting-started deployment controls its own edge

The default getting-started deployment SHALL be a single host the operator controls, fronted by a plain reverse proxy that terminates TLS and forwards requests without content inspection, so the authenticated agent ingest and command routes (`POST /api/events`, `POST /api/enroll`, `GET /api/commands`, `PUT /api/commands/*`) are never subjected to a managed web application firewall. The authenticated bearer token, not edge content inspection, SHALL be the control for this machine-to-machine traffic. A deployment whose public edge runs a content-inspecting WAF the operator cannot disable (a managed PaaS edge) SHALL be supported only when the operator exempts those routes from inspection, and the operator documentation SHALL warn that the edge otherwise blocks agent telemetry.

#### Scenario: Agent telemetry carrying attack signatures reaches the server

- **GIVEN** the default single-host topology whose public edge is a plain reverse proxy with no managed ruleset
- **WHEN** an enrolled agent uploads an event batch whose payloads contain attack signatures (a reverse-shell command line and a C2 URL with a SQL-injection fragment)
- **THEN** the request reaches the server and is handled by the ingest endpoint, accepted and persisted, rather than being blocked by the edge before it arrives

### Requirement: The shared database connection pool is bounded

The system SHALL bound the shared MySQL connection pool with a fixed maximum number of open connections, so that intra-replica processor-worker concurrency multiplied across the replica fleet cannot exhaust the database server's connection limit. The ceiling is a compiled constant sized to the worker count with headroom for request-path queries, not an operator-configurable knob, and it is applied when the process-wide pool is opened.

#### Scenario: Worker concurrency cannot exhaust database connections

- **GIVEN** a replica running its processor workers plus request-path query load
- **WHEN** the workers and request handlers acquire connections concurrently
- **THEN** the total open connections the replica holds is capped at the compiled pool ceiling
- **AND** demand above the ceiling waits for a pooled connection rather than opening an unbounded number

### Requirement: An advisory lock is held for as long as its holder runs

Every advisory lock this system takes SHALL remain held for the whole time its holder is running, regardless of how long that is, and SHALL NOT depend on a database server setting to stay held.

The hazard is specific to how these locks are used. The lock is pinned to one connection while the work runs on a different pooled connection, so for the entire critical section the lock's own connection is idle by construction. Anything that closes an idle connection, a `wait_timeout` an operator tuned down, a proxy, a failover, an administrative kill, frees the lock without the holder being told. The system SHALL therefore keep the lock's connection active for as long as the lock is held, rather than requiring critical sections to be short enough to finish inside whatever the server's idle timeout happens to be.

Losing a lock SHALL NOT be silent. The failure mode this exists to remove is a holder that keeps running after its lock is gone, completes, and reports success: the work looks like it ran under mutual exclusion when for part of its life it did not, and for the per-host event claim that means two claimers folding one host's stream concurrently. So when a lock is lost while its holder runs, the system SHALL cancel the holder's context and SHALL report the loss to the caller as a distinct, inspectable failure rather than an ordinary error, so a caller that needs exclusivity can retry. A holder that fails on its own terms SHALL keep reporting its own error, which is the more specific diagnosis.

Where a lock is handed out without a callback, and so has no context to cancel, the system SHALL still keep it alive and SHALL record the loss, and that form SHALL document that it cannot abort its caller.

#### Scenario: A lock outlives the closing of its idle connection

- **GIVEN** a caller holding an advisory lock while its work runs on a different connection
- **AND** a critical section longer than the database's idle-connection timeout
- **WHEN** the work runs to completion
- **THEN** the lock is still held throughout, because its connection was kept active
- **AND** no other caller enters the section in the meantime

#### Scenario: A lock lost mid-callback is reported, not absorbed

- **GIVEN** a caller running under an advisory lock
- **WHEN** the connection holding that lock is killed while the callback is still running
- **THEN** the callback's context is cancelled
- **AND** the caller is told the lock was lost, distinguishably from failing to acquire it in the first place
- **AND** a callback that returned no error of its own is not reported as a success

#### Scenario: The callback's own failure is not masked by the lock loss

- **GIVEN** a callback that both loses its lock and fails on its own terms
- **WHEN** it returns
- **THEN** the caller sees the callback's own error rather than the lock-loss report

### Requirement: Worker sizing counts only connections that can actually be obtained

When the system sizes its worker fleet against the database connection pool, it SHALL first subtract every connection that is held for the lifetime of the process and therefore never returned to the pool. Today those are the leader-gated periodic sweeps, each of which pins one connection for its advisory lock from boot to shutdown.

Counting a permanently pinned connection as available is not a rounding error, it is the same stall the sizing check exists to prevent: the fleet is sized against connections that are never coming back, so workers pin what is left for their locks and then wait forever for a claim connection that no one will release. The result is a pipeline that boots cleanly and processes nothing.

The reserved count SHALL be supplied by whatever wires those long-lived holders, not assumed by the component doing the sizing, so that adding or removing a sweep cannot leave the sizing silently wrong.

Only holders that are actually running SHALL be counted. A sweep that is switched off returns immediately when it is given the lock, so its connection is taken and released in brief bursts rather than held; counting it would make the sizing pessimistic and could refuse a pool that is in fact adequate, which is the opposite of the failure this exists to prevent.

Where the remaining budget cannot serve even one worker, the system SHALL refuse to start rather than reduce the fleet, and the threshold it enforces SHALL be the threshold its error reports, including the reservation. A guard that admits a value its own message calls insufficient is worse than no guard: it produces a running deployment whose configuration was already diagnosed as unusable. Once the refusal is honest, the system SHALL NOT floor the computed worker count to a minimum of one, because the refusal already guarantees one is affordable and a floor could only ever manufacture a worker the pool cannot serve.

#### Scenario: A pool with room for the sweeps but not for a worker is refused

- **GIVEN** a connection pool large enough for the leader-gated sweeps but with too little left for one worker
- **WHEN** the processor is constructed with a coordinator
- **THEN** construction fails rather than starting a worker that would stall on its first claim
- **AND** the error names the pool size the deployment needs, counting the reservation

#### Scenario: A budget the guard's own advice rejects is refused rather than reduced

- **GIVEN** a connection budget smaller than the threshold the refusal message tells operators to reach
- **WHEN** the processor is constructed with a coordinator
- **THEN** construction fails
- **AND** the fleet is not silently reduced to a worker that cannot make progress

#### Scenario: Reserving the long-lived holders does not shrink a healthy deployment

- **GIVEN** the shipped connection pool, the shipped worker count, and the leader-gated sweeps reserved
- **WHEN** the processor is constructed
- **THEN** the configured worker count is honored in full
- **AND** no reduction is reported
