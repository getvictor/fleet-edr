## MODIFIED Requirements

### Requirement: Deliveries carry a signed, versioned payload

Each webhook request SHALL carry a versioned JSON envelope containing a unique event id, the event type, the event time, the delivery attempt number, and the triggering host. An alert event SHALL additionally carry the alert (its id, severity, status, source, title, rule identity, rule attribution, MITRE techniques, and timestamps) together with the process context and a console link to the alert. A host health event SHALL carry the health episode in place of the alert, and SHALL NOT carry an alert body, because it describes no alert. A status-change event SHALL additionally carry the previous status. The payload SHALL NOT contain any signing secret or agent credential. Each request SHALL be signed with HMAC-SHA256 over the request id, timestamp, and body, carried in dedicated identifier, timestamp, and signature headers named per the Standard Webhooks convention (`webhook-id`, `webhook-timestamp`, `webhook-signature`), so that a receiver recomputing the signature with the shared secret obtains the same value. The envelope SHALL round-trip: decoding a serialized envelope and re-encoding it reproduces the same document.

The change from the prior requirement is that the alert body is scoped to alert events rather than required of every request. It was written when every delivery was an alert. The envelope of an alert event is unchanged: its alert body is present exactly as before, so an existing receiver reading alert deliveries sees the same document.

#### Scenario: A creation event carries the versioned alert envelope

- **GIVEN** a delivery for a newly created alert
- **WHEN** the request is built
- **THEN** the body is a versioned envelope carrying the event id, event type, event time, attempt number, the alert fields, host and process context, and the console link

#### Scenario: A delivery credits the author of the rule that fired

- **GIVEN** a delivery for an alert raised by a vendored rule that credits an upstream author
- **WHEN** the request is built
- **THEN** the envelope names that author alongside the rule identity

#### Scenario: A status-change event carries the previous status

- **GIVEN** a delivery for an alert whose status changed from open to resolved
- **WHEN** the request is built
- **THEN** the envelope carries both the new status and the previous status

#### Scenario: The signature verifies with the shared secret and differs by secret

- **GIVEN** two destinations configured with different secrets
- **WHEN** the same alert is delivered to each
- **THEN** a receiver recomputing HMAC-SHA256 over the request id, timestamp, and body with its own secret obtains the sent signature, and the two signatures differ

#### Scenario: The envelope round-trips

- **GIVEN** any valid delivery envelope
- **WHEN** it is decoded and re-encoded
- **THEN** the result equals the original document

#### Scenario: The payload never contains the signing secret

- **GIVEN** any delivery
- **WHEN** the body is inspected
- **THEN** it contains no signing secret and no agent credential

#### Scenario: An alert envelope is unchanged by the health event type

- **GIVEN** a delivery for an alert event
- **WHEN** the request body is built
- **THEN** it serializes to the same document it did before host health events existed

## ADDED Requirements

### Requirement: Host health episodes are delivered

A destination SHALL be able to subscribe to host health episodes opening, filtered by the same minimum severity that filters alert events. When an episode opens, the system SHALL durably enqueue one delivery to each enabled destination subscribed to that event whose minimum severity the episode's severity meets.

Its envelope SHALL carry the episode: its kind, the component and the part of it at fault, the fault's own machine-readable detail, its severity and title, and the instant it began as observed on the host. It SHALL carry the host it concerns.

A delivery SHALL name exactly one subject, an alert or a health episode, and the delivery store SHALL reject a row that names both or neither.

Delivery SHALL be idempotent per episode and destination. The episode and its delivery are written by different parts of the system and cannot share one transaction, so a failure between the two writes causes the triggering report to be processed again. The enqueue SHALL therefore be attempted again on that reprocessing even though the episode is by then already recorded, and SHALL collapse onto any delivery already enqueued, so that the retry recovers a lost notification without producing a second one.

An episode closing SHALL NOT be delivered by this requirement.

#### Scenario: An episode opening reaches a subscribed destination

- **GIVEN** an enabled destination subscribed to health episodes opening, with a minimum severity the episode meets
- **WHEN** a host health episode opens
- **THEN** exactly one delivery is enqueued to that destination
- **AND** its envelope carries the episode and the host, and no alert body

#### Scenario: A destination not subscribed to health episodes receives nothing

- **GIVEN** an enabled destination subscribed only to alert events
- **WHEN** a host health episode opens
- **THEN** no delivery is enqueued to that destination

#### Scenario: The minimum severity filters health episodes

- **GIVEN** a destination subscribed to health episodes opening with a minimum severity above the episode's
- **WHEN** the episode opens
- **THEN** no delivery is enqueued to that destination

#### Scenario: A lost enqueue is recovered on reprocessing without a duplicate

- **GIVEN** a health episode that was recorded but whose delivery was not enqueued before processing failed
- **WHEN** the triggering report is processed again
- **THEN** the episode is not recorded a second time
- **AND** the delivery is enqueued once
- **AND** processing it a further time enqueues nothing more

#### Scenario: A delivery names exactly one subject

- **GIVEN** the delivery store
- **WHEN** a row names both an alert and a health episode, or neither
- **THEN** the store rejects it
