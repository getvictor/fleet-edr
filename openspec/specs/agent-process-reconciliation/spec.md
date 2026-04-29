# Agent Process Reconciliation Specification

## Purpose

Endpoint security event streams are best-effort. Under kernel back-pressure, extension crashes, or agent restarts, exit
notifications go missing and the server's process tree accumulates rows that look like they are still running long after
the underlying process has terminated. The agent's process reconciliation pass closes that gap from the host side by
periodically asking the kernel directly which tracked process identifiers are still alive and synthesizing exit events for
the ones that are not.

The capability is the host-side complement to a server-side time-to-live reconciler. The server fallback eventually marks
stale rows as exited based on a long inactivity window, but that window is too coarse for an interactive UI. The agent's
local sweep gives operators near-minute-granularity convergence on busy hosts while remaining explicit about provenance:
synthetic exits carry a distinct reason code so the UI can tell them apart from observed exits.

## Requirements

### Requirement: Periodic kill-zero sweep

The system SHALL periodically probe each tracked process identifier with the operating-system liveness probe (signal zero)
and treat a "no such process" response as evidence the process has exited.

#### Scenario: Tracked process is still alive

- **GIVEN** a process identifier exists in the agent's in-memory process table and the kernel reports it as live
- **WHEN** the reconciliation pass probes that identifier
- **THEN** no synthetic exit event is enqueued for that identifier
- **AND** the table entry is preserved

#### Scenario: Tracked process has exited without a notification

- **GIVEN** a process identifier exists in the agent's in-memory process table but the kernel reports "no such process"
- **WHEN** the reconciliation pass probes that identifier
- **THEN** a synthetic exit event is enqueued for that identifier
- **AND** the entry is removed from the in-memory process table

#### Scenario: Probe is blocked by permissions

- **GIVEN** the kernel reports "permission denied" rather than confirming or denying liveness
- **WHEN** the reconciliation pass probes that identifier
- **THEN** the entry is treated as alive and no synthetic exit is emitted
- **AND** the entry remains in the table

### Requirement: Synthetic exits are distinguishable

The system MUST tag every synthetic exit event with a reason code that identifies it as host-side reconciliation, so
downstream analysis and the UI can distinguish reconciled exits from kernel-observed exits.

#### Scenario: Synthetic exit shape

- **GIVEN** the reconciler decides to enqueue a synthetic exit
- **WHEN** the event is built
- **THEN** the event's type is "exit"
- **AND** the event carries a reason that identifies it as host-reconciled, not as a kernel-observed clean exit
- **AND** the event uses the current host time and a fresh unique event identifier

### Requirement: Synthetic exits flow through the standard queue

The system SHALL enqueue synthetic exit events through the same local queue used for kernel-observed events, so the uploader
delivers them with the same durability and dedup guarantees as the rest of the telemetry stream.

#### Scenario: Enqueue path is the standard queue

- **GIVEN** the reconciler has decided to emit a synthetic exit for a process identifier
- **WHEN** the event is constructed
- **THEN** it is enqueued through the same interface kernel-observed events use
- **AND** it inherits the queue's durability, batching, and dedup-on-server semantics

### Requirement: Reconciliation respects the freshly-observed window

The system MUST skip process identifiers that were first observed less than a configured minimum-age window ago, so the
agent does not race against in-flight kernel-to-server propagation and falsely reconcile a process that just spawned.

#### Scenario: Newly observed process

- **GIVEN** a process identifier was first observed within the configured minimum-age window
- **WHEN** the reconciliation pass runs
- **THEN** that identifier is skipped for this pass regardless of its kernel liveness state
- **AND** it is reconsidered on a future pass once it ages past the window

### Requirement: Per-pass cap on synthetic exits

The system SHALL cap the number of synthetic exits emitted in a single reconciliation pass so a pathological gap of many
thousands of missed exits cannot saturate the queue in one tick.

#### Scenario: Many stale entries at once

- **GIVEN** the table contains a number of stale entries that exceeds the configured per-pass cap
- **WHEN** the pass runs
- **THEN** the pass emits at most the configured number of synthetic exits
- **AND** the remaining stale entries are reconciled by subsequent passes

### Requirement: Skip when host identity is unknown

The system MUST skip the reconciliation pass when the agent has no current host identifier, so synthetic events are never
emitted with an empty or placeholder host identifier.

#### Scenario: Enrollment has not yet completed

- **GIVEN** the agent has not yet completed enrollment and holds no host identifier
- **WHEN** the reconciliation interval fires
- **THEN** the pass exits immediately without probing or emitting anything
- **AND** subsequent passes resume normally once enrollment completes

### Requirement: Per-entry failures do not stall the pass

The system SHALL log and continue when an individual probe, identifier generation, or enqueue fails, so a single bad entry
cannot prevent the rest of the pass from making progress.

#### Scenario: Enqueue fails for one entry

- **GIVEN** the reconciler probes several identifiers and one of the synthetic exits fails to enqueue
- **WHEN** the failure occurs
- **THEN** the failure is logged with the offending process identifier
- **AND** the pass continues with the remaining identifiers
- **AND** the failed entry remains in the table to be retried on a future pass

