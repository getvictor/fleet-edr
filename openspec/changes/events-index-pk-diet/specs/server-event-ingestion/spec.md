# Server event ingestion: index and primary-key diet delta

## MODIFIED Requirements

### Requirement: Idempotent submission by event_id

The system SHALL treat the `event_id` as the unique logical identity of an event. A re-submission of an event with the same `event_id` SHALL be silently dropped without raising an error so that an agent can safely retry a batch after a transient network failure. The uniqueness guarantee is independent of the physical storage layout: `event_id` MAY be persisted as a unique key over a compact surrogate primary key rather than as the primary key itself, and the deduplication, foreign-key references, and all `event_id`-keyed reads MUST behave identically either way.

#### Scenario: An agent retries a batch after a network failure

- **GIVEN** a batch that was already persisted on a prior request
- **WHEN** the agent submits the same batch again
- **THEN** the system responds with HTTP 200
- **AND** the previously stored events are not duplicated and existing rows are not overwritten

#### Scenario: A batch mixes new and previously seen events

- **GIVEN** a batch where some `event_id` values were persisted before and some are new
- **WHEN** the agent submits the batch
- **THEN** the system responds with HTTP 200
- **AND** the new events are persisted while the previously seen events remain unchanged

## ADDED Requirements

### Requirement: Event storage keeps secondary indexes compact

The system SHALL minimize the per-row secondary-index footprint of the `events` table so index storage does not dominate disk on high-volume hosts. The physical primary key MUST be compact (a fixed-width surrogate), so each secondary-index entry carries a small primary-key copy rather than a full event identifier. The system MUST NOT carry secondary indexes that are strictly subsumed by another index's left prefix or that serve no query.

#### Scenario: A duplicate event is still rejected with a compact key layout

- **GIVEN** the events table keyed by a compact surrogate primary key with `event_id` as a unique key
- **WHEN** an event with an already-stored `event_id` is submitted
- **THEN** the duplicate is silently dropped and no second row is created

#### Scenario: Alert evidence still resolves to its events

- **GIVEN** an alert linked to one or more events by `event_id`
- **WHEN** the alert detail is read
- **THEN** the linked events resolve through the `event_id` reference unchanged
