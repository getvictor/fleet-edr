# Endpoint Event Collection Specification

## Purpose

Endpoint event collection is the on-device telemetry source for the Fleet EDR product. It captures the security-relevant
operating-system activity that downstream detection rules, the process-tree UI, and incident-response workflows depend on:
process lifecycle (exec / fork / exit / open), outbound and inbound network flows attributed to the originating process,
and DNS queries with their resolved answers. Without this layer there is no signal — every other component in the system
is consuming or relaying what this capability emits.

The behavior described here is the contract agents and the server depend on. It defines what events appear, what fields
each event carries, how events are uniquely identified, and how the host that produced them is identified, so that the
ingest path, the storage schema, and the React UI can reason about the wire format without reading device source code.

## Requirements

### Requirement: Process lifecycle event capture

The system SHALL emit a `fork` event when a monitored process forks, an `exec` event when a process replaces its image,
an `exit` event when a process exits, and an `open` event when a process opens a file. Each event MUST carry the
originating PID and any additional fields documented for that event type.

#### Scenario: A user runs a shell command

- **GIVEN** the endpoint event capture is running
- **WHEN** a user launches `/bin/ls` from a shell
- **THEN** the system emits an `exec` event whose payload includes the new image path, the argument vector, the parent
  PID, the effective UID and GID, and the code-signing identity (team ID, signing ID, platform-binary flag) when the
  binary is signed
- **AND** the system later emits an `exit` event for the same PID with the process exit status

#### Scenario: A daemon forks a worker

- **GIVEN** the endpoint event capture is running
- **WHEN** a process calls `fork(2)` without a subsequent exec
- **THEN** the system emits a `fork` event whose payload identifies the parent PID and the child PID

### Requirement: Process exec authorization

The system SHALL evaluate every exec against the active blocklist before allowing the new image to run. When the target
binary path is on the blocklist the system MUST deny the exec so the image never executes; otherwise the system MUST
allow the exec and emit a notification event for it.

#### Scenario: An exec of a blocklisted path is denied

- **GIVEN** the active policy contains a path on its blocklist
- **WHEN** any process attempts to exec that path
- **THEN** the system denies the exec so the kernel returns the standard "operation not permitted" error to the caller
- **AND** the binary does not run

#### Scenario: An exec of a non-blocklisted path is allowed

- **GIVEN** the active policy does not contain the target path
- **WHEN** a process execs that path
- **THEN** the system allows the exec
- **AND** an `exec` event is emitted describing the new image

### Requirement: Outbound socket flow capture

The system SHALL emit a `network_connect` event for every outbound socket flow seen by the network filter, attributing
the flow to the source process. Inbound flows SHALL be tagged with `direction = inbound`. The system MUST NOT block
flows on the basis of capture; capture is observation-only.

#### Scenario: A process opens an outbound TCP connection

- **GIVEN** the network filter is enabled
- **WHEN** a process initiates an outbound TCP connection to a remote endpoint
- **THEN** the system emits a `network_connect` event whose payload identifies the source PID, the source binary path,
  the effective UID, the protocol (`tcp` or `udp`), the direction (`outbound`), the remote address, the remote port, the
  local address, the local port, and — when the system can derive it from the flow — the remote hostname
- **AND** the flow is allowed to proceed unmodified

### Requirement: DNS query capture

The system SHOULD emit a `dns_query` event for each DNS query seen by the DNS proxy when DNS proxying is enabled, and a
follow-on `dns_query` event carrying the resolved addresses when the upstream resolver replies. Capture failures MUST
NOT prevent the query or its response from being forwarded to the originally-intended resolver.

#### Scenario: An application resolves a hostname over UDP

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a UDP DNS query for a hostname
- **THEN** the system forwards the query unchanged to the originally-intended resolver
- **AND** the system emits a `dns_query` event identifying the source PID, source path, effective UID, query name,
  query type, and protocol (`udp`)
- **AND** when the resolver replies with one or more addresses the system emits a follow-on `dns_query` event carrying
  the resolved addresses in `response_addresses`

#### Scenario: A DNS query that cannot be parsed is still forwarded

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a DNS query whose payload the proxy cannot parse for telemetry
- **THEN** the system forwards the query to the originally-intended resolver
- **AND** the system does not emit a `dns_query` event for the unparsed payload

### Requirement: Canonical event envelope

Every event the system emits SHALL be serialized as a JSON envelope with the fields `event_id`, `host_id`,
`timestamp_ns`, `event_type`, and `payload`. `event_id` MUST be a UUID unique to that event, `host_id` MUST identify the
device that produced the event and MUST be stable across reboots of that device, `timestamp_ns` MUST be nanoseconds
since the Unix epoch, and `event_type` MUST be one of the documented values (`exec`, `fork`, `exit`, `open`,
`network_connect`, `dns_query`).

#### Scenario: An event envelope is well-formed

- **GIVEN** any captured event
- **WHEN** the system serializes the event
- **THEN** the resulting bytes parse as a JSON object containing `event_id`, `host_id`, `timestamp_ns`, `event_type`,
  and `payload`
- **AND** `event_type` matches one of the documented enum values
- **AND** the payload conforms to the schema for that event type

#### Scenario: Events from the same device share a host_id

- **GIVEN** an enrolled device producing events
- **WHEN** the device emits events from any source (process, network, DNS)
- **THEN** every emitted event carries the same `host_id` value
- **AND** that value persists across reboots of the device

### Requirement: Reconciliation events are tagged

The system SHALL distinguish synthesized reconciliation events from kernel-observed events. Synthetic exit events
emitted to close out processes whose kernel exit notification was missed SHALL carry `exit_reason = host_reconciled`,
and synthetic exec events emitted at startup to materialize processes that already existed before subscription SHALL
carry `snapshot = true`.

#### Scenario: Agent fills a missing exit event

- **GIVEN** a process disappeared from the kernel without producing an exit event
- **WHEN** the reconciliation pass detects the absent process
- **THEN** the system emits an `exit` event for the missing PID with `exit_reason = host_reconciled`

#### Scenario: Extension restarts and rebuilds the live process set

- **GIVEN** the system extension has just started
- **WHEN** the system enumerates processes that already existed before subscription began
- **THEN** the system emits one `exec` event per such process with `snapshot = true`
- **AND** detection rules ignore those events because they describe historical state

### Requirement: Capture is non-fatal on individual event errors

The system SHALL continue capturing subsequent events when serialization, attribution, or upstream forwarding of a
single event fails. A single malformed event MUST NOT take the capture pipeline offline.

#### Scenario: One event fails to serialize

- **GIVEN** the capture pipeline is running
- **WHEN** a single event cannot be serialized into the canonical envelope
- **THEN** the system drops that one event
- **AND** the system continues capturing and emitting subsequent events
