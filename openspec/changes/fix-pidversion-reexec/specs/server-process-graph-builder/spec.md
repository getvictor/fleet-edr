# server-process-graph-builder delta: a re-exec generation records its own kernel generation

## MODIFIED Requirements

### Requirement: Same-PID re-exec chain

The system SHALL preserve the full sequence of exec generations on a single PID. When an `exec` event arrives for a PID that already has an exec'd record, the system MUST close the prior generation and create a new linked record so that a chain like `python -> sh -> bash -> payload` is visible in its entirety.

Each generation SHALL record the kernel PID generation (`pidversion`) reported by its own `exec` event, because execve increments that generation and the new image therefore has an identity the generation it replaced does not share. When the `exec` event reports no `pidversion`, the new generation MUST record none rather than inheriting the value of the generation it replaced: an absent identity leaves the record unpinned, which downstream consumers already handle by falling back to the event-time window, whereas an inherited one names a generation that no longer exists and causes a response action aimed at that record to be refused.

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

#### Scenario: An exec event without a kernel generation records none

- **GIVEN** a process record already exec'd on some PID and carrying a `pidversion`
- **WHEN** an `exec` event replaces the image on the same PID without an intervening fork and reports no `pidversion`
- **THEN** the new generation records no `pidversion`
- **AND** it does not inherit the `pidversion` of the generation it replaced

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
