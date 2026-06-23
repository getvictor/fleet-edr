# Server event ingestion: index diet delta

## ADDED Requirements

### Requirement: Event storage drops redundant indexes

The system SHALL NOT carry secondary indexes on the `events` table that are strictly subsumed by another index's left prefix or that serve no query, so index storage does not dominate disk on high-volume hosts. Specifically, an index on `host_id` alone and an index on `event_type` alone are redundant (the former is a left-prefix of an existing composite; the latter matches no query, since every event-type predicate is anchored by a leading `host_id`) and MUST NOT be present. Indexes that a query relies on MUST be retained, including the index backing the unprocessed-event claim (`processed, host_id, timestamp_ns`) and the index backing per-process network/DNS correlation.

#### Scenario: A duplicate event is still rejected after the index diet

- **GIVEN** the events table with the redundant `host_id`-only and `event_type`-only indexes removed
- **WHEN** an event with an already-stored `event_id` is submitted
- **THEN** the duplicate is silently dropped and no second row is created

#### Scenario: The unprocessed-event claim still works after the index diet

- **GIVEN** the events table with the redundant indexes removed
- **WHEN** the processor claims a batch of unprocessed events ordered by host and time
- **THEN** the claim is served by the retained `(processed, host_id, timestamp_ns)` index and returns the batch
