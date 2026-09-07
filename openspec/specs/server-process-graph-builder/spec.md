# Server Process Graph Builder Specification

## Purpose

The process graph builder is the materialization layer that converts the raw `fork`, `exec`, and `exit` event stream into a per-host process forest. It is the canonical representation used by the detection engine, the host process tree UI, and the per-process detail view; without it, every reader would have to reconstruct lineage from raw events on each query.

The capability owns the invariants of process identity over time: which fork started a process, which exec gave it its current image, when it exited, how PID reuse is disambiguated across generations, and how a same-PID re-exec chain is preserved so the UI can show the full transformation sequence rather than just the final image.

## Requirements

### Requirement: Timestamp-ordered batch processing

The system SHALL process events in non-decreasing timestamp order within a batch so that for any single PID the `fork` is applied before any subsequent `exec` and any subsequent `exit`. The order in which the agent transmitted the events MUST NOT alter the resulting process forest.

#### Scenario: Events arrive out of order in a batch

- **GIVEN** a batch containing a `fork`, an `exec`, and an `exit` for the same PID submitted in arbitrary order
- **WHEN** the builder processes the batch
- **THEN** the resulting process record reflects the fork's parent linkage, the exec's image and arguments, and the exit's code, as if the events had been processed strictly in timestamp order

### Requirement: Fork creates a process record

The system SHALL create a new process record on receipt of a `fork` event. The record MUST capture the host, the new PID, the parent PID, and the fork timestamp.

A fork-without-exec child has no image of its own, so the system SHALL give it the parent's image path. That path MUST be resolved as of the fork's OWN timestamp: the system MUST select the newest generation of the parent PID that had forked at or before that instant. Resolving by parent PID alone MUST NOT be done, because PIDs are reused and a fork is routinely materialized after its parent's PID has been recycled, so the newest generation of that PID at materialization time is not in general the one that forked the child. A generation that forked AFTER the child cannot be the child's parent, and that is the whole of the constraint. The resolution MUST be identical whether the batch is applied as a set or event by event, since the batched path is the production one.

Selecting the generation is not sufficient on its own, because a same-PID re-exec chain preserves the ORIGINAL fork timestamp on every image it holds and distinguishes those rows by their exec timestamp alone. Within the selected generation the system SHALL therefore resolve the image in force at the fork's timestamp: the latest image whose exec landed at or before that instant. Selecting by row recency instead MUST NOT be done, because it returns whatever the PID ran LAST and so hands the child an image its parent had not yet executed, which is the same misattribution one level down from the recycled-PID case. When no image in the chain had been applied yet, the child's timestamp falls inside its parent's own fork-to-exec window, and the system SHALL fall back to the chain's EARLIEST image rather than discard the generation and attribute the child to an older one. That window is reachable because fork and exec are stamped independently at handler time, so their errors are independent and a child's fork can carry a stamp below its parent's exec even when it truly followed it. The pre-exec image itself is unrecoverable, since the first exec after a fork updates that row in place, so the chain's first image is the closest surviving evidence. Where two generations of one PID carry the SAME fork timestamp, which the PID-reuse sweep permits because it closes only rows stamped strictly earlier, that timestamp cannot separate them and the resolution ranks their images together. The system SHALL then answer with the latest image application at or before the instant, in preference to breaking the tie by insertion order, because insertion order is the very thing this requirement exists to stop depending on. This is a documented ambiguity rather than a resolution, and separating such generations by the kernel generation counter is tracked separately. This resolution SHALL be expressed by comparing timestamps and MUST NOT subtract them: intake rejects only a zero timestamp, so any other int64 reaches this resolution, and a difference between a negative instant and one near the maximum overflows. In the persisted store that surfaces as an out-of-range error rather than a wrapped value, which would fail the lookup for every fork on that host instead of mis-ranking a single image.

The system MUST NOT additionally require the parent generation to be recorded as still alive at the fork's timestamp. A parent is alive when its child forks, by construction, so an aliveness test can never correct the answer here; it can only discard the sole candidate on the strength of an exit timestamp, and those timestamps are the least reliable data the record holds. The extension stamps events at handler time, and the PID-reuse sweep SYNTHESIZES an exit at the recycling fork's timestamp, so a record stating that a parent exited before its own child forked is a record that is wrong rather than a parent that is disqualified. Requiring aliveness was measured on 154,660 never-exec'd rows: it blanked the inherited path on 29,880 of them while correcting 3,413 FEWER than the fork bound alone, a roughly 4:1 net loss of information. A parent generation with no observed exit MUST likewise still supply the path, so that a host whose exit events are late, reordered, or dropped does not stop inheriting paths.

The record MUST carry no inherited path when, and only when, no generation of the parent PID had forked yet at the child's fork timestamp. An absent path states that the parent's image is unknown, which is the honest answer where no candidate exists; asserting an image the parent could not have been running is not, because the process tree, the process detail view, and every detection rule that gates on the process path then read it as fact.

#### Scenario: A daemon forks a worker

- **GIVEN** a `fork` event carrying child PID and parent PID
- **WHEN** the builder applies the event
- **THEN** a process record exists for the host and child PID with the parent PID and fork timestamp set
- **AND** the record has no exec metadata and no exit metadata yet

#### Scenario: A fork arrives after its parent's PID was recycled

- **GIVEN** two generations of one parent PID, an earlier one that ran a known image, and a later one that recycled the PID and runs a different image
- **WHEN** a `fork` event stamped before the later generation forked is applied after both generations are already recorded
- **THEN** the child record carries the earlier generation's image path
- **AND** it does not carry the recycling generation's image path
- **AND** a `fork` stamped at or after the later generation's fork carries the later generation's path instead
- **AND** the result is the same whether the earlier generation ended at an observed exit or was closed by the PID-reuse sweep

#### Scenario: A parent whose exit was never observed still supplies the path

- **GIVEN** a parent generation that ran a known image and whose exit event never arrived
- **WHEN** a `fork` event naming it as parent is applied
- **THEN** the child record carries that generation's image path

#### Scenario: A parent recorded as exited before its child forked still resolves

- **GIVEN** a parent PID whose newest recorded generation ran a known image and carries an exit timestamp earlier than a later instant
- **WHEN** a `fork` event stamped at that later instant naming that PID as parent is applied
- **THEN** the child record carries that generation's image path
- **AND** the recorded exit does not disqualify it, since a parent cannot fork after it dies and the exit record is therefore the unreliable half

#### Scenario: No generation of the parent PID had forked yet

- **GIVEN** a parent PID whose every recorded generation forked after a given instant
- **WHEN** a `fork` event stamped at that instant naming that PID as parent is applied
- **THEN** the child record carries no inherited path
- **AND** it does not carry the path of a generation that did not yet exist

#### Scenario: A fork resolves the image in force inside a re-exec chain

- **GIVEN** a parent PID whose generation exec'd one image and later re-exec'd into a second, both rows carrying the generation's original fork timestamp
- **WHEN** a child's fork timestamp falls between the two execs
- **THEN** the child inherits the image in force at that instant, not the later one the PID ran afterwards
- **GIVEN** instead a child whose fork timestamp falls before the generation's first exec had been applied
- **WHEN** its path is resolved
- **THEN** the generation is still selected and the chain's earliest image is inherited, rather than the child being attributed to an older generation of that PID

#### Scenario: An extreme timestamp pair cannot defeat the image ordering

- **GIVEN** a parent generation forked at a negative instant whose later image exec'd at the maximum representable timestamp
- **WHEN** a child forked between the two execs resolves its inherited path
- **THEN** it inherits the image in force at its own timestamp, and the resolution neither overflows nor fails

### Requirement: Exec updates image metadata

The system SHALL update the in-flight process record on receipt of an `exec` event by setting the image path, the argument vector, the effective UID and GID, the code-signing identity, and the SHA-256 of the executed binary when the agent provided them. The fork-time parent linkage MUST NOT be lost as a side effect.

#### Scenario: A user runs a shell command

- **GIVEN** a process record created by a prior `fork`
- **WHEN** an `exec` event arrives for the same host and PID
- **THEN** the process record carries the exec timestamp, image path, argument vector, UID, GID, code-signing identity, and binary hash from the event
- **AND** the parent PID and fork timestamp from the original `fork` are preserved

### Requirement: Exit closes the process record

The system SHALL set the exit timestamp and exit code on the in-flight process record on receipt of an `exit` event.

#### Scenario: A process exits normally

- **GIVEN** an in-flight process record for a host and PID
- **WHEN** an `exit` event arrives for the same host and PID
- **THEN** the process record carries the exit timestamp and the exit code from the event
- **AND** the record is no longer considered in-flight for subsequent events on the same PID

### Requirement: PID reuse creates a new generation

The system SHALL recognize that operating-system PIDs are reused. When a `fork` event arrives for a PID that already has a non-exited record, the system MUST close the prior record and create a new record for the new generation so the two generations remain distinguishable in the forest.

Only a generation that started BEFORE the incoming fork SHALL be closed. PID reuse means a new fork takes over a PID an older generation held, so a non-exited record whose own fork timestamp is at or after the incoming fork's timestamp is not the generation being displaced: it is a later generation that was merely materialized first, which happens whenever concurrently processed claim batches split a fork/exec pair and deliver the exec's batch first (the exec synthesizes its record stamped at the exec time, and the fork then arrives with an earlier timestamp). Closing such a record produced an impossible lifetime, with an exit timestamp earlier than its own fork timestamp.

The system MUST NOT write a process record whose exit timestamp precedes its own fork timestamp. Such a record is invisible to every point-in-time process lookup, because those lookups bracket on the record being alive at the event time. That silently redirected flow-to-process correlation onto the bare fork record for the same PID, whose path is only the parent's inherited image, and a rule gating on the process path then declined the process as unremarkable instead of matching the exec'd image.

#### Scenario: A new fork lands on a stale PID

- **GIVEN** an existing process record for a host and PID whose original exit was never observed
- **WHEN** a `fork` event arrives for the same host and PID with a different parent
- **AND** the incoming fork's timestamp is later than the existing record's fork timestamp
- **THEN** the prior record is closed at the new fork's timestamp
- **AND** a new process record is created for the new generation with its own fork metadata

#### Scenario: A fork arrives after the exec-synthesized record for the same PID

- **GIVEN** a process record synthesized by an `exec` event, stamped with the exec's timestamp as its fork timestamp
- **WHEN** a `fork` event for the same host and PID arrives afterwards carrying an EARLIER timestamp
- **THEN** the exec-synthesized record is left open, because it did not start before the incoming fork and so is not a generation the fork displaces
- **AND** no process record has an exit timestamp earlier than its own fork timestamp
- **AND** a point-in-time lookup at the exec's timestamp resolves the exec-imaged record, not a bare fork record for the same PID

### Requirement: Exec without prior fork is tolerated

The system SHALL synthesize a process record when an `exec` event arrives for a PID that has no in-flight record. This covers extension-startup snapshots and processes that existed before the agent began capturing.

#### Scenario: An exec arrives for an unseen PID

- **GIVEN** no process record for a host and PID
- **WHEN** an `exec` event arrives for that host and PID
- **THEN** a new process record is created with the exec metadata and a fork timestamp set to the exec time as a best effort earliest-known moment

### Requirement: Same-PID re-exec chain

The system SHALL preserve the full sequence of exec generations on a single PID. When an `exec` event arrives for a PID that already has an exec'd record, the system MUST close the prior generation and create a new linked record so that a chain like `python -> sh -> bash -> payload` is visible in its entirety.

Each generation SHALL record the kernel PID generation (`pidversion`) reported by its own `exec` event, because execve increments that generation and the new image therefore has an identity the generation it replaced does not share. Recording the replaced generation's value instead names an identity that no longer exists and causes a response action aimed at that record to be refused. When the `exec` event reports no `pidversion` at all, the new generation MUST keep the value of the generation it replaced: the agent derives the generation it enforces against from this same event stream, so an event that reports none leaves both sides holding the replaced value and therefore agreeing, and the record stays pinned well enough to still reject a response action aimed at a recycled PID, which arrives with a distant generation. Recording none in that case would instead drop the pin entirely and admit a response action that identifies its target by PID alone. This is the same rule the first `exec` after a fork already applies when it images its fork record.

#### Scenario: A shell exec-optimization chain runs on one PID

- **GIVEN** a process record that has already been exec'd at least once
- **WHEN** another `exec` event arrives for the same host and PID without an intervening fork
- **THEN** the prior generation is closed at the new exec's timestamp
- **AND** a new process record is created carrying a back-reference to the prior generation
- **AND** the prior generations are retrievable in order as the re-exec chain for that process

#### Scenario: A re-exec generation records its own kernel generation

- **GIVEN** a process record already exec'd as a shell and carrying that shell's `pidversion`
- **WHEN** an `exec` event replaces the image on the same PID without an intervening fork, reporting the new image's `pidversion`
- **THEN** the new generation records the `pidversion` its own exec event reported
- **AND** the closed generation keeps the `pidversion` it was stored with
- **AND** the two generations of that PID do not share a `pidversion`

#### Scenario: An exec event without a kernel generation keeps the replaced one

- **GIVEN** a process record already exec'd on some PID and carrying a `pidversion`
- **WHEN** an `exec` event replaces the image on the same PID without an intervening fork and reports no `pidversion`
- **THEN** the new generation keeps the `pidversion` of the generation it replaced
- **AND** the record stays pinned, so a response action identifying that PID by a different generation is still refused

### Requirement: Network and DNS events are linked to the process at event time

The system SHALL link `network_connect` and `dns_query` events to the process record for the originating host and PID. When the event carries a `pidversion`, the system MUST restrict candidate generations to those matching the exact `(host_id, pid, pidversion)` identity, which immunises the link against PID reuse without clock-drift padding. The identity is not guaranteed to select a single generation, because records written before generations recorded their own `pidversion` inherited the value of the generation they replaced and those repeats remain in place for the life of the record: when the identity matches exactly one generation the system MUST link to it regardless of whether the event timestamp falls inside its lifetime window, and when the identity matches more than one generation the system MUST use the event's timestamp to select the generation that was the running image at the event time, and MUST NOT link the event to a generation carrying a different `pidversion` merely because of timestamp proximity. When the event carries no `pidversion`, or no generation matches that exact identity, the system MUST fall back to linking the event to the process record that was alive on that host and PID at the event's timestamp, and a network or DNS event MUST NOT be associated with a stale generation that exited before the event or with a future generation that had not yet forked.

#### Scenario: A short-lived process opens a connection

- **GIVEN** a process record with a known fork-to-exit lifetime on a host
- **WHEN** the per-process detail view is requested
- **THEN** the network and DNS events surfaced for that record are limited to those whose host and PID match and whose timestamps fall inside the process lifetime

#### Scenario: A flow with pidversion correlates to the exact generation across PID reuse

- **GIVEN** two process generations on the same host and PID with distinct `pidversion`s, one exited and one alive
- **WHEN** a `network_connect` event carrying the alive generation's `pidversion` is correlated
- **THEN** the event is linked to the generation whose `pidversion` matches
- **AND** the link does not depend on the connect timestamp falling inside that generation's lifetime window

#### Scenario: A flow within a re-exec chain links to the generation running at the event time

- **GIVEN** two exec generations on the same host and PID that share one `pidversion`, an earlier generation that has exited and a later generation that is alive
- **WHEN** a `network_connect` event carrying that shared `pidversion` and a timestamp inside the earlier generation's running window is correlated
- **THEN** the event is linked to the earlier generation, the one that was the running image at the event time, not the later or live generation
- **AND** a flow carrying the same `pidversion` whose timestamp falls inside the later generation's window links to the later generation

#### Scenario: A flow without pidversion falls back to the event-time window

- **GIVEN** a `network_connect` event that carries no `pidversion`
- **WHEN** the event is correlated to a process on the same host and PID
- **THEN** the system links it to the generation that was alive at the event's timestamp using the event-time lifetime rule

### Requirement: Snapshot exec events are stitched but not treated as new activity

The system SHALL accept `exec` events flagged as snapshot (events synthesized by the agent at startup to materialize processes that existed before subscription) and use them to populate the process forest, while signaling to downstream consumers that they describe pre-existing state rather than new activity. The system MUST mark the resulting process records as snapshot-originated and seed a freshness timestamp on them so the freshness-TTL reconciler can distinguish them from organic rows.

#### Scenario: Extension restarts and replays the live process set

- **GIVEN** a batch containing one or more `exec` events with the snapshot flag set
- **WHEN** the builder applies the batch
- **THEN** the corresponding process records are created or updated so the UI can render Safari, Slack, Finder, and other pre-existing processes
- **AND** each created record carries a snapshot-originated marker
- **AND** each created record carries a freshness timestamp equal to its fork time so it is not eligible for immediate TTL reconciliation on the first pass after insert
- **AND** the snapshot flag is preserved on the underlying events so detection rules can distinguish historical state from newly observed activity

### Requirement: Snapshot heartbeat events extend the freshness window

The system SHALL, for each `snapshot_heartbeat` event, update the freshness timestamp on the matching snapshot-originated process record. The update MUST be scoped to records that are flagged snapshot-originated AND still live, so a stray heartbeat for a recycled PID cannot resurrect an exited row and cannot apply to a non-snapshot row.

The freshness update is applied at ingest time, and the heartbeat is not retained as an `events` row (see the server-event-ingestion capability). The process graph builder retains its heartbeat-handling path only for heartbeat rows that were persisted before this behavior shipped and remain unprocessed at upgrade time; such legacy rows are handled with the identical scoping. The freshness scoping and its no-op cases are unchanged regardless of which path applies the update.

#### Scenario: Heartbeat for a live snapshot row bumps freshness

- **GIVEN** a snapshot-originated process record that has not exited
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** the record's freshness timestamp is updated to the heartbeat's timestamp

#### Scenario: Heartbeat for an exited row is a no-op

- **GIVEN** a snapshot-originated process record that has an exit timestamp set
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** the record's freshness timestamp is NOT updated
- **AND** no other field on the record changes

#### Scenario: Heartbeat for a non-snapshot row is a no-op

- **GIVEN** a process record that originated from kernel fork/exec events rather than the startup snapshot
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** no field on the record changes

#### Scenario: A heartbeat does not create or retain an event row

- **GIVEN** an enrolled host with a live snapshot-originated process record for PID P
- **WHEN** a `snapshot_heartbeat` for PID P is ingested
- **THEN** the freshness timestamp is updated
- **AND** no retained `events` row exists for that heartbeat

### Requirement: TTL reconciliation respects snapshot freshness

The system SHALL periodically force-close process records whose freshness window has elapsed without observed activity, synthesizing an exit time and marking the row with a TTL-reconciliation reason code. The freshness window MUST use the record's freshness timestamp when set (which the snapshot path seeds and heartbeats update) and fall back to the fork timestamp otherwise, so heartbeated snapshot rows are exempt while ordinary rows whose exit events went missing remain subject to the existing freshness-TTL safety net.

#### Scenario: Snapshot row with fresh heartbeats survives TTL

- **GIVEN** a snapshot-originated process record whose freshness timestamp was updated within the TTL window
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is NOT closed
- **AND** the record's exit fields remain unset

#### Scenario: Snapshot row without recent heartbeats is closed

- **GIVEN** a snapshot-originated process record whose freshness timestamp is older than the TTL window
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is force-closed with the TTL-reconciliation exit reason
- **AND** the synthesized exit timestamp lands at the freshness timestamp plus the TTL window, so the UI can render the reconciled exit at a meaningful moment rather than at the extension-startup snapshot moment

#### Scenario: Non-snapshot row with missing exit is closed (issue #6 regression guard)

- **GIVEN** a process record that originated from a fork event, whose fork timestamp is older than the TTL window, and whose freshness timestamp is unset
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is force-closed with the TTL-reconciliation exit reason
- **AND** the synthesized exit timestamp lands at the fork timestamp plus the TTL window

### Requirement: Completed process records are pruned after the retention window

The system SHALL delete process records whose recorded exit time is older than the configured retention window, on the same cadence and cutoff as event retention, so the processes table does not grow without bound on long-lived hosts. The prune MUST key on the exit time, never on the fork time, so a still-running record (no exit time, which includes the live snapshot working set) is never deleted and a long-running process that only recently exited is retained for the full window measured from its exit. The prune MUST skip any process record still referenced by an alert so alert detail views continue to resolve their originating process. Records whose exit event went missing are first force-closed by the freshness-TTL reconciler and become eligible for this prune once their synthesized exit time ages past the window.

#### Scenario: A completed record older than the window is pruned

- **GIVEN** a process record with an exit timestamp older than the retention window
- **AND** no alert references the record
- **WHEN** a retention pass runs
- **THEN** the record is deleted

#### Scenario: A live record is never pruned

- **GIVEN** a process record with no exit timestamp, whose fork timestamp is older than the retention window
- **WHEN** a retention pass runs
- **THEN** the record is NOT deleted

#### Scenario: A completed record referenced by an alert is retained

- **GIVEN** a process record with an exit timestamp older than the retention window
- **AND** an alert references the record
- **WHEN** a retention pass runs
- **THEN** the record is NOT deleted

### Requirement: Exit-before-snapshot-exec race buffer

The system SHALL handle the race in which a kernel-observed `exit` event for a PID is processed BEFORE the snapshot `exec` event for the same PID is processed. Because the snapshot exec arrives last but describes an earlier moment, the exit's update would otherwise find no row and the later snapshot exec would synthesize a phantom alive row that survives until TTL. The builder MUST buffer such unmatched exits briefly and consume them when the companion snapshot exec arrives, producing a single record that is born already-exited.

#### Scenario: Exit arrives before its companion snapshot exec

- **GIVEN** an `exit` event for a host and PID with no existing record
- **AND** within a short bounded window the matching snapshot `exec` event for the same host and PID arrives
- **WHEN** the builder processes both
- **THEN** the resulting process record exists, is marked snapshot-originated, and is born with the exit timestamp, exit reason, and exit code from the buffered exit
- **AND** no phantom alive row is produced for that PID

#### Scenario: Exit arrives without a matching snapshot exec within the window

- **GIVEN** an `exit` event for a host and PID with no existing record
- **AND** no matching snapshot `exec` event arrives within the bounded buffer window
- **WHEN** the buffer window elapses
- **THEN** the buffered exit is discarded
- **AND** no record is synthesized for that PID
- **AND** a much-later snapshot exec for the same PID is treated as a fresh insert without inheriting the long-expired exit, so a recycled PID cannot pick up a stale exit

### Requirement: Process records store the full macOS uid and gid range

The system SHALL persist process effective UID and GID values across the entire macOS `uid_t`/`gid_t` range (unsigned 32-bit, 0 through 4294967295), including the conventional `nobody` value (4294967294) and the unset `KAUTH_UID_NONE` sentinel (4294967295). A UID or GID anywhere in that range MUST NOT cause the originating event to be rejected at persistence time.

#### Scenario: A process owned by nobody is materialized

- **GIVEN** an `exec` event whose UID is 4294967294 and GID is 4294967295
- **WHEN** the builder processes the event
- **THEN** the process record persists with UID 4294967294 and GID 4294967295

### Requirement: A single unpersistable event does not stall batch processing

The system SHALL isolate a single event that fails with a permanent (non-retryable) error so that it does not block the rest of its batch or any subsequent batch. A permanent error is one that recurs identically on every retry: a payload that cannot be parsed (a JSON syntax or type error), or a value the database can never store (a data-integrity violation). Such an event MUST be dropped, and logged, while the remaining events in the batch are still materialized and the batch is reported successful so the processor marks it processed rather than re-fetching it. An event that fails with a transient (retryable) error MUST instead cause the batch to be reported as failed so the processor retries it and no data is lost to a recoverable fault.

#### Scenario: A poison event is dropped and the batch advances

- **GIVEN** a batch containing one event that fails with a permanent data error and one valid event
- **WHEN** the builder processes the batch
- **THEN** the valid event's process record is materialized
- **AND** the batch is reported successful so the processor marks it processed and does not retry it
- **AND** the poison event is not stored

#### Scenario: A malformed event is dropped and the batch advances

- **GIVEN** a batch containing one event whose payload cannot be parsed and one valid event
- **WHEN** the builder processes the batch
- **THEN** the valid event's process record is materialized
- **AND** the batch is reported successful so the processor marks it processed and does not retry it
- **AND** the malformed event is not stored

#### Scenario: A transient failure retries the batch

- **GIVEN** an event that fails with a transient, retryable database error
- **WHEN** the builder classifies the failure
- **THEN** the failure is reported as non-permanent so the batch is retried rather than the event being dropped

### Requirement: Process records carry the kernel PID generation

The system SHALL store the originating process's kernel PID generation (`pidversion`) on the process record when an `exec` or `fork` event provides it, so that a process generation is identifiable by the exact `(host_id, pid, pidversion)` triple in addition to its fork-to-exit lifetime. The field is optional: an event that does not carry `pidversion` (a legacy agent, or a flow whose audit token was unavailable) MUST still materialize a process record, with the `pidversion` left unset. A re-exec generation on the same PID inherits the same `pidversion` as its predecessor, because the kernel generation does not change across `execve` without an intervening fork.

#### Scenario: An exec event carrying pidversion stores it on the record

- **GIVEN** the graph builder is processing a batch
- **WHEN** an `exec` event for a host and PID carries a `pidversion`
- **THEN** the materialized process record stores that `pidversion`
- **AND** the record is retrievable by the exact `(host_id, pid, pidversion)` triple

#### Scenario: An exec event without pidversion still materializes a record

- **GIVEN** the graph builder is processing a batch
- **WHEN** an `exec` event for a host and PID carries no `pidversion`
- **THEN** the materialized process record is created with its `pidversion` left unset
- **AND** the record remains retrievable by host, PID, and event-time lifetime as before

### Requirement: Set-based batch materialization is equivalent to per-event application

The system SHALL materialize a batch using a bounded, small number of database round-trips that does not grow one-or-more per event: it MUST resolve the candidate process rows for the batch's `(host_id, pid)` set with a single bulk read, fold the batch against an in-memory model that reproduces the per-event resolution semantics (timestamp ordering, fork creation, exec-in-place update, exit closure, PID-reuse closure, exec-without-fork synthesis, same-PID re-exec chain linkage, snapshot dedup and freshness seeding, and the exit-before-snapshot-exec buffer), and persist the result with set-based writes. The resulting process forest MUST be identical to the forest produced by applying the same events one at a time in timestamp order, for any batch.

#### Scenario: Batched materialization equals per-event materialization

- **GIVEN** a batch of `fork`, `exec`, `exit`, and snapshot `exec` events, including same-PID re-exec sequences and PID reuse, applied to a host's current process forest
- **WHEN** the builder materializes the batch with its set-based path
- **THEN** the resulting process records (parent linkage, exec image and metadata, exit timestamps and reasons, re-exec chain back-references, snapshot markers and freshness timestamps) are identical to those produced by applying the same events individually in timestamp order

#### Scenario: A poison data error is isolated under batched persistence

- **GIVEN** a batch whose set-based write would fail because one row carries a value the database can never store (a permanent data-integrity violation) alongside otherwise-valid rows
- **WHEN** the builder flushes the batch
- **THEN** the offending row is dropped and logged, the remaining rows are materialized, and the batch is reported successful so the processor marks it processed and does not retry it
- **AND** a transient (retryable) write fault instead fails the whole batch so the processor retries it and no data is lost

### Requirement: Re-processing a batch is idempotent

The graph builder MUST be idempotent under re-processing: applying the same batch of fork/exec/exit/snapshot/heartbeat events more than once SHALL yield the identical process forest as applying it once, with no duplicate generations, no fabricated re-exec generations, no phantom PID-reuse closes, and no freshness regressions. This is required because the detection processor nacks and re-claims a batch on a retryable evaluation miss, and a claim-lease-expiry re-offer can replay a stalled or crashed worker's events, so the same events are folded through the builder more than once. Idempotency is anchored on the event that materialized each row: a row records the id of the event that created it and the id of the event that applied its current exec image and its exit, and the builder skips an event whose effect is already recorded. An observed exit MUST NOT close a process that forked after the exit, and a heartbeat's freshness bump MUST only advance (never move backward), so a replayed exit or heartbeat cannot corrupt a later generation of a reused PID that a prior pass already materialized.

#### Scenario: Re-applying the same batch yields the same forest

- **GIVEN** a batch of fork/exec/exit/snapshot/heartbeat events that the builder has already processed once, materializing a process forest
- **WHEN** the identical batch is processed a second time (a nack-and-re-claim, or a claim-lease-expiry re-offer)
- **THEN** the process forest is unchanged: the same rows, the same generations and re-exec chain, and the same exit and freshness state
- **AND** no duplicate process rows, fabricated re-exec generations, or phantom PID-reuse closes are created

### Requirement: Sibling aggregation collapses repeated leaf execs

The system SHALL provide a read-time transform over the per-host process forest that collapses repeated identical child executions under the same parent into a single aggregated node, so that a parent that spawned N childless children of the same binary identity renders as one node carrying a count rather than N nodes. Two children have the same binary identity when they share the same parent AND the same image path AND the same content hash AND the same code-directory hash. Parent identity is part of the key because the transform also runs over the forest roots, which are not guaranteed to share a real parent (a node becomes a root when its real parent is unresolvable in the queried window), so without it two orphaned leaves of the same binary but distinct lineages would wrongly merge. The aggregated node MUST carry the group's total count, the split of that count into exited and running members (a running member has no observed exit), and the earliest and latest fork times in the group. The earliest member (by fork time, with the row id as the tie-breaker for equal fork times) is the representative that supplies the aggregated node's visible process fields, so the label and identity are deterministic; the aggregated node's own identifier MUST be distinct from that representative and from every real process so an aggregated group and its members never collide. The transform MUST be order-preserving and lossless: it MUST NOT drop or duplicate any process, the total number of underlying processes MUST be preserved (the sum of every aggregated node's count plus one per individual node equals the input leaf count at each level), and the output siblings MUST be deterministically ordered by first fork time. Only childless siblings are eligible to fold; a child that has its own subtree MUST remain an individual node so its descendants are never silently removed. A group smaller than the aggregation threshold MUST remain individual nodes rather than becoming a count-of-one aggregate. Aggregation MUST be opt-outable so a caller can obtain the raw, un-aggregated forest.

#### Scenario: Aggregation preserves every leaf and its order

- **GIVEN** a parent with an arbitrary batch of childless children of varying image paths, binary identities, fork times, and exit states
- **WHEN** the forest is aggregated
- **THEN** the sum of every aggregated node's count plus one for each individual node equals the number of input children
- **AND** no underlying process is dropped, duplicated, or moved to a group of a different binary identity
- **AND** the output siblings are ordered by first fork time
- **AND** each aggregated node's exited and running counts sum to its total count and its first fork time is no later than its last

#### Scenario: N identical-path children collapse into one node

- **GIVEN** a parent that spawned several childless children sharing one image path and binary identity, some exited and some still running
- **WHEN** the forest is aggregated
- **THEN** those children are represented by a single aggregated node carrying the group count, the exited-versus-running split, and the earliest and latest fork times

#### Scenario: A child with its own subtree is never folded away

- **GIVEN** a parent whose children include both repeated childless execs and a child that itself has descendants
- **WHEN** the forest is aggregated
- **THEN** the childless repeats collapse into an aggregated node
- **AND** the child that has descendants remains an individual node with its subtree intact, whose own repeated children may aggregate one level down

#### Scenario: Same path but different binary is not merged

- **GIVEN** two childless children under one parent that share an image path but differ in content hash
- **WHEN** the forest is aggregated
- **THEN** they remain two separate nodes rather than one aggregated node

### Requirement: A process lookup at an instant returns the image that was running then

The system SHALL resolve a process lookup at an instant to the generation whose IMAGE was running at that instant, and SHALL NOT resolve it by when the process was forked.

The two differ whenever a process replaces its image. Executing preserves the fork time, so every generation of one pid carries the same one, and ordering by it cannot distinguish them: the answer becomes whichever generation happened to be recorded last. For a process that forked a child and then executed something else, that is an image which had not run when the child was forked.

A generation that has forked and not yet executed SHALL still be resolvable, at its fork instant, because that is the only start instant such a generation has.

This matters because it is the lookup that answers every parent-image and attribution question. A wrong answer costs the detection and not only its label: a parent that executed something benign after the fork reads as benign, so the rule that would have fired does not.

#### Scenario: A parent that re-executed after the fork still reports the forking image

- **GIVEN** a process that forked a child and then replaced its image with a different binary
- **WHEN** the process is looked up at the instant it forked the child
- **THEN** the image it was running at that instant is returned, not the one it adopted afterwards

#### Scenario: The adopted image is returned once it is running

- **GIVEN** the same process after it has replaced its image
- **WHEN** it is looked up at or after that instant
- **THEN** the adopted image is returned

#### Scenario: A generation that has not executed is still resolvable

- **GIVEN** a generation that forked and has not executed
- **WHEN** it is looked up at its fork instant
- **THEN** it is returned

### Requirement: Inherited parent path resolves the generation that forked the child

When a fork event carries no parent path of its own, the system resolves it from the parent PID's own record, and SHALL answer with the generation of that PID which was running at the child's fork instant.

Two generations of one PID CAN share a fork timestamp: a stale generation is closed only when a strictly earlier stamp is seen, and the sensor stamps events when it handles them rather than when they occur, so an exact collision is not prevented upstream. Where two records share a stamp AND the image ordering cannot separate them, the system SHALL prefer the one whose kernel generation counter is higher, and SHALL NOT resolve that tie by the order in which the records were ingested. Ingest order is not evidence: a later generation's fork is routinely materialized before an earlier one's, which is why the inherited path was wrong often enough to be worth fixing in the first place.

The qualification is load-bearing rather than hedging. Where the records DO differ in which image was in force at the instant, that difference decides, even if it selects the record with the lower kernel counter. Preferring the counter there would select a chain's newest image regardless of the instant being asked about, which is the re-exec error the image ordering exists to prevent, so the kernel counter is a tie-break within the existing ordering and not an override of it.

Where one record carries a kernel generation and the other does not, and the image ordering again cannot separate them, the system SHALL prefer the one that does, so the outcome follows the available evidence rather than the storage layer's ordering of absent values.

A record whose image was never applied at all SHALL NOT outrank one whose image was applied at the same instant. Both describe an image starting at the same moment, so every ordering key up to that point ties, and the record that never exec'd still carries the path it inherited at fork. Preferring it reports the pre-exec image for an instant at which the process HAD executed. The tie SHALL fall through to the kernel generation instead, which is what separates two records the image ordering genuinely cannot.

The key that prefers the EARLIEST image SHALL apply only to records whose image had not been applied by the instant, which is the group it exists for. Applied to every record it decides nothing for the group it was written for, where each record has an image starting in the future, while silently reversing the case above for records that had been applied.

The kernel generation SHALL be consulted only AFTER the image ordering has selected within a generation, never before it. That counter increments on exec as well as on fork, so the records of a single re-exec chain carry ascending values; ranked earlier it would select a chain's newest image regardless of the instant being asked about, which is the re-exec error the image ordering exists to prevent. It therefore decides only between generations that the image ordering cannot separate.

Both implementations of this lookup, the stored query and the in-batch overlay, SHALL order identically. An ordering corrected in one and not the other makes the answer depend on whether a parent happened to be processed in the same batch as its child.

#### Scenario: Two generations sharing a fork timestamp are separated by kernel generation

- **GIVEN** two generations of one PID recorded with the same fork timestamp and neither having exec'd
- **AND** the generation with the LOWER kernel counter was ingested last
- **WHEN** a child's inherited parent path is resolved at an instant after both forks
- **THEN** the path of the generation with the higher kernel counter is returned
- **AND** the answer does not depend on the order the two records were ingested in

#### Scenario: A generation carrying kernel evidence outranks one without

- **GIVEN** two generations of one PID recorded with the same fork timestamp
- **AND** only one of them carries a kernel generation counter
- **WHEN** a child's inherited parent path is resolved
- **THEN** the path of the generation carrying the counter is returned

#### Scenario: A never-executed row does not win

- **GIVEN** two records of one PID sharing a fork timestamp, one that never exec'd and one whose exec landed at that same instant
- **WHEN** a child's inherited parent path is resolved at a later instant
- **THEN** the record that never exec'd does not win on the strength of having no exec
