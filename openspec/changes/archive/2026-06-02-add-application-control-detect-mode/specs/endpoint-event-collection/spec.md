# Endpoint Event Collection Specification (delta)

## ADDED Requirements

### Requirement: Application control would-block event kind

The system SHALL emit an event of kind `application_control_would_block` whenever the extension's
application control decision engine returns a `BLOCK` decision for an AUTH_EXEC whose matched
rule's `enforcement` is `DETECT`. The event SHALL carry, in addition to the canonical envelope
fields, `policy_id`, `policy_version`, `rule_id`, `rule_type`, `rule_identifier`,
`matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url` (nullable), `process`, and
`ancestry`. Field shapes match `application_control_block` exactly; the two kinds differ only in
which path of the decision engine produced them and which alert subtype the detection-rules
engine stamps on the resulting alert.

#### Scenario: A DETECT match produces a would-block event

- **GIVEN** a rule whose precedence walk matches a specific exec target with
  `enforcement=DETECT`
- **WHEN** the extension allows the AUTH_EXEC
- **THEN** the extension emits an `application_control_would_block` event carrying the rule and
  matched identifier
- **AND** the canonical exec channel observes the allowed attempt for normal telemetry purposes

### Requirement: Every AUTH_EXEC decision emits a corresponding exec event

The system SHALL emit a regular `exec` event for every AUTH_EXEC the kernel raises, regardless of
the decision the application control decision engine returned. The exec event's payload SHALL
carry an optional `decision` field whose value is `'blocked'` for AUTH-denied execs (matched a
PROTECT BLOCK rule), `'would_block'` for AUTH-allowed-but-flagged execs (matched a DETECT BLOCK
rule), and absent for ordinary allowed execs (no rule match). Catalog detection rules and the
graph builder consume the regular exec event for every shape; the optional `decision` field lets
downstream views distinguish ordinary execs from AUTH-flagged execs without joining across event
kinds.

#### Scenario: A blocked AUTH_EXEC emits both the block event and a regular exec event

- **GIVEN** a PROTECT BLOCK rule matches an exec
- **WHEN** the extension denies the AUTH_EXEC
- **THEN** an `application_control_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='blocked'`

#### Scenario: A would-blocked AUTH_EXEC emits both the would-block event and a regular exec event

- **GIVEN** a DETECT BLOCK rule matches an exec
- **WHEN** the extension allows the AUTH_EXEC
- **THEN** an `application_control_would_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='would_block'`

#### Scenario: An ordinary allowed exec emits a regular exec event with no decision field

- **GIVEN** no rule matches an exec
- **WHEN** the extension allows the AUTH_EXEC
- **THEN** a regular `exec` event is emitted
- **AND** the event payload contains no `decision` field

## MODIFIED Requirements

### Requirement: Process exec authorization

The system SHALL consult the application control decision engine on every AUTH_EXEC before allowing
the new image to run. When the engine returns a rule whose `action=BLOCK` and
`enforcement=PROTECT`, the system MUST deny the exec so the image never executes and SHALL emit an
`application_control_block` event plus a regular `exec` event with `decision='blocked'`. When the
engine returns a rule whose `action=BLOCK` and `enforcement=DETECT`, the system MUST allow the
exec and SHALL emit an `application_control_would_block` event plus a regular `exec` event with
`decision='would_block'`. When the engine returns no match, the system MUST allow the exec and
SHALL emit a regular `exec` event with no `decision` field. Decisions MUST be reached within the
AUTH_EXEC deadline; the system MUST NOT block the AUTH callback on signing-information fetches and
MUST treat as-yet-uncached identifiers as silent misses for their rule types.

The change from the prior requirement is the explicit `enforcement=DETECT` branch (which the Phase
A spec contradicted itself on) and the explicit requirement that AUTH-denied execs ALSO emit a
regular exec event so the graph builder and catalog rules observe the attempt. The Phase A spec's
"Otherwise the system MUST allow the exec and emit an exec event" implication that the deny path
skipped the exec event is reversed here.

#### Scenario: A PROTECT block denies the exec and emits both events

- **GIVEN** the decision engine returns a `BLOCK` / `PROTECT` rule for an exec target
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system denies the exec so the kernel returns the standard "operation not permitted"
  error
- **AND** the binary does not run
- **AND** an `application_control_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='blocked'`

#### Scenario: A DETECT match allows the exec and emits both events

- **GIVEN** the decision engine returns a `BLOCK` / `DETECT` rule for an exec target
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system allows the exec
- **AND** the binary runs
- **AND** an `application_control_would_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='would_block'`

#### Scenario: An allowed exec emits an exec event with no decision field

- **GIVEN** the decision engine returns no match for an exec target
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system allows the exec
- **AND** a regular `exec` event is emitted describing the new image
- **AND** the event payload contains no `decision` field

#### Scenario: A cold-cache exec on a CERTIFICATE-only target is allowed

- **GIVEN** the snapshot contains only a `CERTIFICATE` rule for an exec target
- **AND** the leaf certificate SHA-256 for that target is not yet cached
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the `CERTIFICATE` rule silently misses for this exec
- **AND** the system allows the exec
- **AND** the cache is filled for subsequent execs
- **AND** a regular `exec` event is emitted with no `decision` field

### Requirement: Canonical event envelope

Every event the system emits SHALL be serialized as a JSON envelope with the fields `event_id`,
`host_id`, `timestamp_ns`, `event_type`, and `payload`. `event_id` MUST be a UUID unique to that
event, `host_id` MUST identify the device that produced the event and MUST be stable across
reboots of that device, `timestamp_ns` MUST be nanoseconds since the Unix epoch, and `event_type`
MUST be one of the documented values (`exec`, `fork`, `exit`, `open`, `network_connect`,
`dns_query`, `application_control_block`, `application_control_would_block`).

The change from the prior requirement adds `application_control_would_block` to the documented
`event_type` enum.

#### Scenario: An event envelope is well-formed

- **GIVEN** any captured event
- **WHEN** the system serializes the event
- **THEN** the resulting bytes parse as a JSON object containing `event_id`, `host_id`,
  `timestamp_ns`, `event_type`, and `payload`
- **AND** `event_type` matches one of the documented enum values
- **AND** the payload conforms to the schema for that event type

#### Scenario: Events from the same device share a host_id

- **GIVEN** an enrolled device producing events
- **WHEN** the device emits events from any source (process, network, DNS, application control)
- **THEN** every emitted event carries the same `host_id` value
- **AND** that value persists across reboots of the device
