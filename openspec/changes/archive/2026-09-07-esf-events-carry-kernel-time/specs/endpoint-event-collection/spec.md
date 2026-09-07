# endpoint-event-collection

## MODIFIED Requirements

### Requirement: Canonical event envelope

Every event the system emits SHALL be serialized as a JSON envelope with the fields `event_id`, `host_id`, `timestamp_ns`, `event_type`, and `payload`. `event_id` MUST be a UUID unique to that event, `host_id` MUST identify the device that produced the event and MUST be stable across reboots of that device, `timestamp_ns` MUST be nanoseconds since the Unix epoch, and `event_type` MUST be one of the documented values (`exec`, `fork`, `exit`, `open`, `network_connect`, `dns_query`).

`timestamp_ns` SHALL record when the KERNEL observed the event, not when the agent finished handling it. For every event derived from an Endpoint Security message the system SHALL take the stamp from that message's own event time. Sampling the wall clock at serialization instead records handler latency, and that latency is not small: an exec is serialized after the handler's synchronous hash and code-signing work, measured at 701ms after the true exec on a loaded host. Because the server correlates a network flow to the process that produced it by comparing these stamps, a late process stamp can place a process AFTER the flow it produced, and the correlation then finds nothing and reports nothing. It also makes every time-correlated detection load-dependent, so fast scripted chains are missed while slow interactive ones are caught.

An event that does not originate from a kernel message, such as a state reconciliation or a boot-time process snapshot, SHALL carry the time it was produced, because there is no kernel instant for it to report.

#### Scenario: An event envelope is well-formed

- **GIVEN** any captured event
- **WHEN** the system serializes the event
- **THEN** the resulting bytes parse as a JSON object containing `event_id`, `host_id`, `timestamp_ns`, `event_type`, and `payload`
- **AND** `event_type` matches one of the documented enum values
- **AND** the payload conforms to the schema for that event type

#### Scenario: Events from the same device share a host_id

- **GIVEN** an enrolled device producing events
- **WHEN** the device emits events from any source (process, network, DNS)
- **THEN** every emitted event carries the same `host_id` value
- **AND** that value persists across reboots of the device

#### Scenario: A kernel event is stamped with the kernel's own event time

- **GIVEN** a kernel message reporting an event that occurred at a known instant
- **WHEN** the system serializes an event from that message, after doing work that takes measurable time
- **THEN** the envelope's `timestamp_ns` is the instant the kernel reported, not the instant serialization ran
- **AND** the value is nanoseconds since the Unix epoch, on the same clock the server compares other events against

#### Scenario: An event with no kernel message behind it is stamped when produced

- **GIVEN** an event that reports state read by the agent rather than a kernel event, such as a reconciliation or a boot-time snapshot
- **WHEN** the system serializes it
- **THEN** the envelope carries the time the event was produced, because no kernel instant exists for it
