# Endpoint Event Collection Specification

## ADDED Requirements

### Requirement: Event payload schema is selected by event type

The published event schema SHALL select which payload definition applies from the envelope's `event_type`, and SHALL NOT select it by requiring the payload to match exactly one definition. Payload definitions overlap by construction: `snapshot_heartbeat_payload` requires only `pid`, so every payload carrying a `pid` satisfies it, and `file_truncate_payload` and `file_delete_payload` are identical in both their required and their declared fields. A schema that selects by matching exactly one definition therefore refuses envelopes the system emits and accepts, which is the opposite of what the document is for.

Every value of the documented `event_type` enum SHALL have exactly one selection clause, and that clause SHALL name a payload definition that exists. An event type without a clause leaves its payload wholly unconstrained while the document still appears to describe it.

The schema SHALL validate the envelopes the system's own emitters produce. The document is mirrored by hand in several emitters and is cited across the agent, the extension and the server as the wire contract, so an emitter that drifts from it MUST be observable rather than silent.

The schema constrains each payload's required fields and their types. It does NOT forbid fields beyond those it declares, because the ingest path accepts them; a payload that carries its own type's required fields plus additional keys is therefore accepted.

#### Scenario: Each documented event type validates

- **GIVEN** the published event schema
- **WHEN** an envelope is validated for each value of the documented `event_type` enum, carrying that type's documented payload
- **THEN** every one of them validates
- **AND** none is refused for matching more than one payload definition

#### Scenario: A mismatched payload is rejected

- **GIVEN** the published event schema
- **WHEN** an envelope carries a payload that does not satisfy the definition its own `event_type` selects
- **THEN** validation fails, naming the field that is missing or ill-typed

#### Scenario: Emitted envelopes validate against the document

- **GIVEN** the envelopes an emitter in this repository produces for its shipped scenarios
- **WHEN** each is validated against the published event schema
- **THEN** every envelope validates, including its `event_id` format

#### Scenario: A payload carrying an undeclared field is accepted

- **GIVEN** the published event schema
- **WHEN** an envelope carries its own event type's required fields plus a field the schema does not declare
- **THEN** it validates, because the ingest path accepts such a payload and the document must not be stricter than what the system accepts

#### Scenario: Every event type has a discriminator clause

- **GIVEN** the published event schema
- **WHEN** its selection clauses are compared against the documented `event_type` enum
- **THEN** each enum value has exactly one clause, and no clause names a type outside the enum
- **AND** each clause names a payload definition the document defines
