## ADDED Requirements

### Requirement: Platform-tagged event envelope

The ingest path SHALL accept an optional `platform` field on each event, where a present value MUST be one of `darwin`, `windows`, or `linux`. The server SHALL reject an event whose platform is present but not one of those values. The server SHALL normalize an absent platform to `darwin`, the default for an agent predating this contract, so that every persisted event carries a concrete platform. The server SHALL persist the platform through both the work queue and the event archive so downstream processing, including rule evaluation, observes it.

#### Scenario: An event carrying a valid platform is accepted

- **GIVEN** an event whose `platform` is `windows`
- **WHEN** the ingest path validates the batch
- **THEN** the event is accepted and its platform is `windows`

#### Scenario: An event without a platform is normalized to darwin

- **GIVEN** an event that omits `platform`
- **WHEN** the ingest path validates the batch
- **THEN** the event is accepted and its platform is `darwin`

#### Scenario: An event with an unknown platform is rejected

- **GIVEN** an event whose `platform` is a value other than darwin, windows, or linux
- **WHEN** the ingest path validates the batch
- **THEN** the request is rejected with status 400 and the error code names the offending index

#### Scenario: Platform survives the queue to rule evaluation

- **GIVEN** a batch containing a windows event and an event with no platform
- **WHEN** the events are fanned out to the work queue the detection engine claims from
- **THEN** the queued windows event carries platform `windows` and the platform-less event carries the normalized `darwin`
