# Endpoint Event Collection Specification (delta)

## ADDED Requirements

### Requirement: Exec events carry signing-identity fields when available

Every `exec` event the system emits SHALL include, when the value is available without blocking the AUTH
callback, the following fields on the new image: `cdhash` (40 hexadecimal characters, present only when the
process runs under Apple's Hardened Runtime), `signing_id` (the developer-assigned signing identifier),
`team_id` (the 10-character Apple Developer Team ID), and `leaf_cert_sha256` (the SHA-256 of the leaf X.509
signing certificate). Each field MAY be absent for unsigned binaries or when its value is not yet cached;
absence does not invalidate the event.

#### Scenario: A signed exec carries signing-identity fields

- **GIVEN** an exec of a binary signed by a non-Apple developer whose code-signing information has been
  cached by an earlier exec
- **WHEN** the extension emits the `exec` event
- **THEN** the event includes `signing_id`, `team_id`, and `leaf_cert_sha256`
- **AND** `cdhash` is present if and only if the binary uses the Hardened Runtime

#### Scenario: A cold-cache exec emits with the missing fields absent

- **GIVEN** an exec of a binary whose `leaf_cert_sha256` is not yet cached
- **WHEN** the extension emits the `exec` event
- **THEN** the event omits `leaf_cert_sha256`
- **AND** the event is otherwise well-formed

### Requirement: Application control block event kind

The system SHALL emit an event of kind `application_control_block` whenever the extension's application
control decision engine returns a `BLOCK` decision for an AUTH_EXEC. The event SHALL carry, in addition to
the canonical envelope fields, `policy_id`, `policy_version`, `rule_id`, `rule_type`, `rule_identifier`,
`matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url` (nullable), `process`, and
`ancestry`. The event SHALL NOT replace the regular `exec` event for the same authorized-but-denied attempt;
both events MAY be emitted for the same AUTH_EXEC so that the regular telemetry pipeline observes the
attempt and the alert pipeline observes the decision.

#### Scenario: A blocked exec produces a block event and a denied exec event

- **GIVEN** a rule whose precedence walk returns BLOCK for a specific exec target
- **WHEN** the extension denies the AUTH_EXEC
- **THEN** the extension emits an `application_control_block` event carrying the rule and matched
  identifier
- **AND** the canonical exec channel observes the denied attempt for normal telemetry purposes

## MODIFIED Requirements

### Requirement: Process exec authorization

The system SHALL consult the application control decision engine on every AUTH_EXEC before allowing the new
image to run. When the engine returns a `BLOCK` rule whose `enforcement=PROTECT`, the system MUST deny the
exec so the image never executes. Otherwise the system MUST allow the exec and emit an `exec` event
describing the new image. Decisions MUST be reached within the AUTH_EXEC deadline; the system MUST NOT block
the AUTH callback on signing-information fetches and MUST treat as-yet-uncached identifiers as silent misses
for their rule types.

#### Scenario: A blocked exec is denied

- **GIVEN** the decision engine returns a `BLOCK` / `PROTECT` rule for an exec target
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system denies the exec so the kernel returns the standard "operation not permitted" error
- **AND** the binary does not run

#### Scenario: An allowed exec emits an exec event

- **GIVEN** the decision engine returns no match for an exec target
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system allows the exec
- **AND** an `exec` event is emitted describing the new image

#### Scenario: A cold-cache exec on a CERTIFICATE-only target is allowed

- **GIVEN** the snapshot contains only a `CERTIFICATE` rule for an exec target
- **AND** the leaf certificate SHA-256 for that target is not yet cached
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the `CERTIFICATE` rule silently misses for this exec
- **AND** the system allows the exec
- **AND** the cache is filled for subsequent execs

### Requirement: Canonical event envelope

Every event the system emits SHALL be serialized as a JSON envelope with the fields `event_id`, `host_id`,
`timestamp_ns`, `event_type`, and `payload`. `event_id` MUST be a UUID unique to that event, `host_id` MUST
identify the device that produced the event and MUST be stable across reboots of that device, `timestamp_ns`
MUST be nanoseconds since the Unix epoch, and `event_type` MUST be one of the documented values (`exec`,
`fork`, `exit`, `open`, `network_connect`, `dns_query`, `application_control_block`).

#### Scenario: An event envelope is well-formed

- **GIVEN** any captured event
- **WHEN** the system serializes the event
- **THEN** the resulting bytes parse as a JSON object containing `event_id`, `host_id`, `timestamp_ns`,
  `event_type`, and `payload`
- **AND** `event_type` matches one of the documented enum values
- **AND** the payload conforms to the schema for that event type

#### Scenario: Events from the same device share a host_id

- **GIVEN** an enrolled device producing events
- **WHEN** the device emits events from any source (process, network, DNS, application control)
- **THEN** every emitted event carries the same `host_id` value
- **AND** that value persists across reboots of the device
