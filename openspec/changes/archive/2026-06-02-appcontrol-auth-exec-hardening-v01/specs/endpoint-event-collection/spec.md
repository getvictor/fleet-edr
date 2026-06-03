# Endpoint event collection v0.1.0 AUTH_EXEC hardening

## ADDED Requirements

### Requirement: Application Control undecided event kind

The system SHALL emit an event of kind `application_control_undecided` whenever the extension's AUTH_EXEC
handler cannot resolve a `BINARY` rule consultation within the kernel deadline budget AND the active
snapshot's `deadline_fallback` posture is `fail-closed` or `audit-only`. The event SHALL carry, in addition
to the canonical envelope fields, `pid`, `path`, `verdict` (`allow` under audit-only, `deny` under
fail-closed), `reason` (`deadline` when the budget was exhausted between SHA-256 chunks, `read_failed`
when the file was unreadable or the `(dev, inode, mtime)` TOCTOU re-stat failed), `file_size_bytes`,
`policy_id`, and `policy_version`. The event SHALL be emitted AFTER the kernel `es_respond_auth_result`
call so the post-respond cost does not eat into the AUTH_EXEC deadline. The `fail-open` posture SHALL NOT
emit the event (an operator who picked fail-open has opted out of cold-cache visibility).

#### Scenario: A fail-closed deadline exceedance emits an undecided event with verdict=deny

- **GIVEN** the active snapshot has `deadline_fallback=fail-closed` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC sync-hash budget is exhausted before the SHA-256 stream completes
- **THEN** the extension emits an `application_control_undecided` event
- **AND** the event's `verdict` is `deny`
- **AND** the event's `reason` is `deadline`
- **AND** the event carries the exec target's `path`, `pid`, `file_size_bytes`, plus the snapshot's
  `policy_id` and `policy_version`

#### Scenario: An audit-only deadline exceedance emits an undecided event with verdict=allow

- **GIVEN** the active snapshot has `deadline_fallback=audit-only` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC sync-hash budget is exhausted before the SHA-256 stream completes
- **THEN** the extension emits an `application_control_undecided` event
- **AND** the event's `verdict` is `allow`
- **AND** the event's `reason` is `deadline`
- **AND** the exec proceeds (the kernel sees `ES_AUTH_RESULT_ALLOW`)

#### Scenario: A fail-open deadline exceedance emits no event

- **GIVEN** the active snapshot has `deadline_fallback=fail-open` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC sync-hash budget is exhausted before the SHA-256 stream completes
- **THEN** the extension does NOT emit an `application_control_undecided` event
- **AND** the exec proceeds (the kernel sees `ES_AUTH_RESULT_ALLOW`)

## MODIFIED Requirements

### Requirement: Canonical event envelope

Every event the system emits SHALL be serialized as a JSON envelope with the fields `event_id`, `host_id`,
`timestamp_ns`, `event_type`, and `payload`. `event_id` MUST be a UUID unique to that event, `host_id` MUST
identify the device that produced the event and MUST be stable across reboots of that device, `timestamp_ns`
MUST be nanoseconds since the Unix epoch, and `event_type` MUST be one of the documented values: `exec`,
`fork`, `exit`, `open`, `network_connect`, `dns_query`, `application_control_block`,
`application_control_undecided`, `snapshot_heartbeat`.

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

### Requirement: Process exec authorization

The system SHALL consult the application control decision engine on every AUTH_EXEC before allowing the new
image to run. The decision engine consults the active snapshot's per-type maps in the fixed precedence order
CDHASH → BINARY → SIGNINGID → TEAMID. When the engine returns a `BLOCK` rule whose `enforcement=PROTECT`,
the system MUST deny the exec so the image never executes. Otherwise the system MUST allow the exec and emit
an `exec` event describing the new image.

The decision MUST be reached within the AUTH_EXEC deadline. For the BINARY rule layer the system MAY block
the AUTH callback on a synchronous SHA-256 compute bounded by `es_message_t.deadline` minus a safety margin
(target: 500 ms) reserved for the post-hash kernel respond + event/notification emit. If the sync compute
cannot complete within that budget OR returns a `(dev, inode, mtime)` TOCTOU mismatch, the snapshot's
`deadline_fallback` posture (`fail-closed` / `fail-open` / `audit-only`) drives the verdict; the BINARY
layer's "could-have-fired" uncertainty SHALL dominate any later-precedence rule that would otherwise have
matched (the walk does NOT continue to SIGNINGID/TEAMID after a deadline-exceeded/read-failed BINARY outcome).

The system MUST NOT block the AUTH callback on `leaf_cert_sha256` fetches (CERTIFICATE rules remain a lazy
cache fill and silently miss on cold cache).

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

#### Scenario: A cold-cache exec on a BINARY-only target is decided synchronously

- **GIVEN** the snapshot contains a `BINARY` block rule for an exec target whose SHA-256 cache is cold
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the system computes the SHA-256 synchronously within the deadline budget
- **AND** the BINARY rule matches
- **AND** the system DENIES the exec on the FIRST attempt
- **AND** an `application_control_block` event is emitted
