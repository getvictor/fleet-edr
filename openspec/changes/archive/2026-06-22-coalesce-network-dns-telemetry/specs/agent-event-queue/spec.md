# Agent event queue: network/DNS coalescing delta

## ADDED Requirements

### Requirement: Pre-enqueue coalescing of repetitive network and DNS telemetry

The agent SHALL coalesce repetitive `network_connect` and `dns_query` events within a bounded time window before they are enqueued, so that a process repeatedly connecting to the same destination or repeatedly resolving the same name is uploaded as a representative event plus an occurrence count rather than one row per occurrence. Coalescing MUST apply only to `network_connect` and `dns_query`; every other event type MUST be enqueued immediately with no added latency.

Within a window, events that share an identity key are merged into one representative. The key is `(pid, pidversion, protocol, direction, remote_address, remote_port)` for `network_connect` and `(pid, pidversion, query_name, query_type)` for `dns_query`. The representative MUST preserve detection-relevant fidelity:

- its envelope timestamp MUST be the earliest occurrence's timestamp, so a downstream correlation window measured backward from a later event is never shortened;
- it MUST carry an occurrence count and the latest occurrence's timestamp so the span and frequency are recoverable;
- for `dns_query` its resolved-addresses set MUST be the union of all addresses observed across the merged events, so a later connection to any resolved address still correlates.

A representative MUST NOT be held longer than one window. The agent MUST flush all buffered representatives on shutdown so a clean stop loses no buffered telemetry. The window is operator-configurable, and a window of zero MUST disable coalescing entirely, restoring per-occurrence enqueue.

#### Scenario: Repeated identical connections collapse to one representative

- **GIVEN** coalescing is enabled with a non-zero window
- **WHEN** a process emits several `network_connect` events with the same identity key within one window
- **THEN** exactly one representative event is enqueued for that key
- **AND** its timestamp equals the earliest occurrence's timestamp
- **AND** its occurrence count equals the number of merged events

#### Scenario: A DNS query and its response merge, preserving all answers

- **GIVEN** coalescing is enabled with a non-zero window
- **WHEN** a process resolves a name and the proxy emits the query event and a follow-on response event for the same key within one window
- **THEN** one representative `dns_query` is enqueued
- **AND** its `response_addresses` is the union of every resolved address observed for that key

#### Scenario: Non-network events are never delayed by coalescing

- **GIVEN** coalescing is enabled
- **WHEN** an `exec`, `fork`, `exit`, `snapshot_heartbeat`, or application-control event is handled
- **THEN** it is enqueued immediately, unchanged, without being buffered

#### Scenario: Buffered representatives are flushed on shutdown

- **GIVEN** coalescing is enabled and one or more representatives are buffered
- **WHEN** the agent is asked to shut down
- **THEN** every buffered representative is enqueued before shutdown completes

#### Scenario: A zero window disables coalescing

- **GIVEN** the coalescing window is configured to zero
- **WHEN** any `network_connect` or `dns_query` event is handled
- **THEN** it is enqueued immediately and unchanged, exactly as without coalescing
