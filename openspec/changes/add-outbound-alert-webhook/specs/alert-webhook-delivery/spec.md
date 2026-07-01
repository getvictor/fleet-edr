## ADDED Requirements

### Requirement: Alert lifecycle events durably enqueue a delivery per matching destination

When the system persists a new alert, or persists an alert status change, it SHALL atomically queue one webhook delivery for every enabled destination whose event-type and minimum-severity filter matches, in the same unit of work that persists the alert. A queued delivery SHALL survive a restart of the server process. If the alert or the status change is not persisted, no delivery SHALL be queued. When no destination matches, alert persistence SHALL proceed unchanged and no delivery is queued. A repeated persist of the same logical alert event (for example a deduplicated alert) SHALL NOT create a second delivery for the same destination.

#### Scenario: A new alert with a matching destination queues one delivery

- **GIVEN** one enabled destination whose filter matches high-severity detection alerts
- **WHEN** a high-severity detection alert is persisted
- **THEN** exactly one delivery for that destination is queued in the same transaction as the alert

#### Scenario: No delivery is queued when the alert does not persist

- **GIVEN** one enabled matching destination
- **WHEN** persisting the alert fails and the transaction rolls back
- **THEN** no delivery is queued

#### Scenario: Alert creation is unaffected when no destination is configured

- **GIVEN** no configured destinations
- **WHEN** an alert is persisted
- **THEN** the alert is persisted normally and no delivery is queued

#### Scenario: A queued delivery survives a restart before it is sent

- **GIVEN** a delivery queued for a reachable destination
- **WHEN** the server process restarts before the delivery is sent
- **THEN** the delivery is still present after restart and is subsequently sent

#### Scenario: A status change queues a delivery for a subscribed destination

- **GIVEN** one enabled destination subscribed to status-change events
- **WHEN** an alert's status changes and the change is persisted
- **THEN** exactly one status-change delivery for that destination is queued in the same transaction

#### Scenario: A deduplicated alert does not double-queue

- **GIVEN** one enabled matching destination and an alert that already produced a queued delivery
- **WHEN** the same logical alert fires again and is deduplicated
- **THEN** no second delivery is queued for that destination and event

### Requirement: Operators manage webhook destinations with a sealed write-only secret

An operator holding `webhook.manage` SHALL be able to create, list, update, disable, and delete webhook destinations, each carrying a name, an https URL, a signing secret, an event-type and minimum-severity filter, and an enabled state. The signing secret SHALL be stored encrypted at rest and SHALL NOT be returned by any read of a destination. Disabling or deleting a destination SHALL stop future deliveries to it.

#### Scenario: Creating a destination does not echo the secret

- **GIVEN** an operator holding `webhook.manage`
- **WHEN** they create a destination with a URL and a signing secret
- **THEN** the destination appears in the list and no read of it returns the signing secret

#### Scenario: Disabling a destination stops future deliveries

- **GIVEN** an enabled destination
- **WHEN** an operator disables it
- **THEN** subsequent matching alerts queue no delivery for that destination

#### Scenario: Updating the secret changes the signing key for later deliveries

- **GIVEN** a destination with an existing secret
- **WHEN** an operator updates the secret
- **THEN** deliveries queued after the update are signed with the new secret

### Requirement: Deliveries carry a signed, versioned payload

Each webhook request SHALL carry a versioned JSON envelope containing a unique event id, the event type, the event time, the delivery attempt number, and the alert (its id, severity, status, source, title, rule identity, MITRE techniques, and timestamps) together with the triggering host and process context and a console link to the alert. A status-change event SHALL additionally carry the previous status. The payload SHALL NOT contain any signing secret or agent credential. Each request SHALL be signed with HMAC-SHA256 over the request id, timestamp, and body, carried in dedicated identifier, timestamp, and signature headers named per the Standard Webhooks convention (`webhook-id`, `webhook-timestamp`, `webhook-signature`), so that a receiver recomputing the signature with the shared secret obtains the same value. The envelope SHALL round-trip: decoding a serialized envelope and re-encoding it reproduces the same document.

#### Scenario: A creation event carries the versioned alert envelope

- **GIVEN** a delivery for a newly created alert
- **WHEN** the request is built
- **THEN** the body is a versioned envelope carrying the event id, event type, event time, attempt number, the alert fields, host and process context, and the console link

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

### Requirement: Delivery is reliable and at-least-once

The delivery worker SHALL attempt each queued delivery until the receiver returns a 2xx response or a bounded retry cap is reached, spacing retries by exponential backoff. Each delivery SHALL carry a stable event id so a receiver can deduplicate repeated attempts. A delivery that exhausts its retry cap SHALL be recorded as failed and surfaced to operators rather than silently dropped. Each delivery attempt SHALL be bounded by a request timeout and a maximum response size so a slow or oversized receiver cannot stall delivery of other alerts. Across multiple server replicas, a queued delivery SHALL be sent without requiring any in-process state to survive a restart, and SHALL NOT be sent concurrently by more than one replica for the same attempt.

#### Scenario: A transient failure is retried then delivered

- **GIVEN** a receiver that returns a 5xx response once and then a 2xx response
- **WHEN** the delivery is processed
- **THEN** it is retried after a backoff and recorded as delivered

#### Scenario: A persistently failing delivery is marked failed after the cap

- **GIVEN** a receiver that always fails
- **WHEN** the delivery reaches its retry cap
- **THEN** it is recorded as failed and surfaced to operators, not silently dropped

#### Scenario: A hung receiver does not stall other deliveries

- **GIVEN** a receiver that never responds
- **WHEN** a delivery to it is attempted
- **THEN** the attempt ends at the request timeout and other queued deliveries continue to be processed

#### Scenario: Repeated attempts share a stable event id

- **GIVEN** a delivery that is retried
- **WHEN** each attempt is sent
- **THEN** every attempt carries the same event id so the receiver can deduplicate

#### Scenario: Two replicas send a delivery once per attempt

- **GIVEN** two server replicas draining the queue
- **WHEN** a single delivery is due
- **THEN** exactly one replica sends it for that attempt

### Requirement: Outbound delivery is protected against SSRF

A destination URL SHALL use https. The system SHALL NOT deliver to, and SHALL NOT follow a redirect to, a URL whose host resolves to a loopback, private, link-local (including the cloud instance-metadata address), or unique-local address, evaluated against the address actually resolved at delivery time. A destination whose URL is not https, or whose host resolves only to a blocked address, SHALL be rejected when an operator saves it.

#### Scenario: A non-https destination URL is rejected on save

- **GIVEN** an operator holding `webhook.manage`
- **WHEN** they save a destination with an `http://` URL
- **THEN** the save is rejected

#### Scenario: A destination resolving to a private address is rejected on save

- **GIVEN** an operator holding `webhook.manage`
- **WHEN** they save a destination whose host resolves only to a private address
- **THEN** the save is rejected

#### Scenario: A host that resolves to the metadata address at send time is not delivered

- **GIVEN** a saved destination whose host resolves to the cloud instance-metadata address at delivery time
- **WHEN** a delivery to it is attempted
- **THEN** the request is not sent to that address

#### Scenario: A redirect to an internal target is not followed

- **GIVEN** a receiver that responds with a redirect to an internal address
- **WHEN** a delivery is attempted
- **THEN** the redirect is not followed

### Requirement: Operators can test a destination and see delivery health

An operator holding `webhook.manage` SHALL be able to send a signed test delivery to a destination and see the immediate outcome (the response status or the error) without creating an alert, and SHALL be able to view recent per-destination delivery outcomes including the latest status, the last error, and success and failure counts. A test delivery SHALL be subject to the same SSRF guards and signing as a real delivery.

#### Scenario: A test delivery to a reachable receiver reports success

- **GIVEN** a destination pointing at a reachable receiver that returns 2xx
- **WHEN** an operator sends a test delivery
- **THEN** the immediate outcome reports success

#### Scenario: A test delivery to an unreachable receiver reports the error

- **GIVEN** a destination pointing at an unreachable receiver
- **WHEN** an operator sends a test delivery
- **THEN** the immediate outcome reports the error

#### Scenario: The status readout reflects the latest outcome

- **GIVEN** a destination that has had a failed delivery followed by a successful one
- **WHEN** an operator views its delivery health
- **THEN** the readout shows the latest successful outcome

#### Scenario: A test delivery to an internal URL is blocked by the SSRF guard

- **GIVEN** a destination whose host resolves to a blocked address
- **WHEN** an operator sends a test delivery
- **THEN** the request is not sent and the outcome reports the destination was blocked
