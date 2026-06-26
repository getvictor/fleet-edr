## ADDED Requirements

### Requirement: Alert evidence is self-contained

When the system persists an alert, it SHALL capture the payloads of the alert's triggering events into durable, alert-scoped storage, in addition to recording their `event_id` values (the "Alert-to-event linkage" requirement). An alert's evidence SHALL remain resolvable independently of the event archive's retention window, so opening an alert returns its triggering-event payloads even after those events have aged out of the event archive. This keeps alert evidence self-contained and removes any dependency of archive retention on a cross-store reference.

#### Scenario: Triggering-event payloads are captured at alert creation

- **GIVEN** an event batch that satisfies one rule's pattern
- **WHEN** the engine persists the resulting alert
- **THEN** the payloads of the alert's triggering events are stored as alert-scoped evidence
- **AND** the alert still records the `event_id` values of those triggering events

#### Scenario: Evidence survives event-archive expiry

- **GIVEN** a persisted alert whose triggering events have since aged out of the event archive
- **WHEN** an operator requests the alert detail
- **THEN** the alert's captured triggering-event payloads are still returned as its evidence
