# Alert webhook delivery

## MODIFIED Requirements

### Requirement: Deliveries carry a signed, versioned payload

Each webhook request SHALL carry a versioned JSON envelope containing a unique event id, the event type, the event time, the delivery attempt number, and the alert (its id, severity, status, source, title, rule identity, rule attribution, MITRE techniques, and timestamps) together with the triggering host and process context and a console link to the alert. A status-change event SHALL additionally carry the previous status. The payload SHALL NOT contain any signing secret or agent credential. Each request SHALL be signed with HMAC-SHA256 over the request id, timestamp, and body, carried in dedicated identifier, timestamp, and signature headers named per the Standard Webhooks convention (`webhook-id`, `webhook-timestamp`, `webhook-signature`), so that a receiver recomputing the signature with the shared secret obtains the same value. The envelope SHALL round-trip: decoding a serialized envelope and re-encoding it reproduces the same document.

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
