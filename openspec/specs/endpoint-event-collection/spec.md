# Endpoint Event Collection Specification

## Purpose

Endpoint event collection is the on-device telemetry source for the Fleet EDR product. It captures the security-relevant operating-system activity that downstream detection rules, the process-tree UI, and incident-response workflows depend on: process lifecycle (exec / fork / exit / open), outbound and inbound network flows attributed to the originating process, and DNS queries with their resolved answers. Without this layer there is no signal: every other component in the system is consuming or relaying what this capability emits.

The behavior described here is the contract agents and the server depend on. It defines what events appear, what fields each event carries, how events are uniquely identified, and how the host that produced them is identified, so that the ingest path, the storage schema, and the React UI can reason about the wire format without reading device source code.

## Requirements

### Requirement: Process lifecycle event capture

The system SHALL emit a `fork` event when a monitored process forks, an `exec` event when a process replaces its image, and an `exit` event when a process exits. Each event MUST carry the originating PID and any additional fields documented for that event type. The `exec` event SHALL additionally carry the process's own kernel PID generation and the `fork` event SHALL carry the child process's kernel PID generation (`pidversion`, read from the respective process's audit token) when it is available, so the server can disambiguate reused PIDs by identity rather than by time. The `pidversion` field is optional: when the audit token is unavailable the event is still emitted without it.

The `exec` event SHALL carry `cdhash`, the code-directory hash of the new image, when the process runs under Apple's Hardened Runtime AND the kernel reported a hash for it. It SHALL omit the field otherwise, in both of the cases that reach that outcome: a process not running under the Hardened Runtime, and a hardened process whose reported hash is all zeros.

Both omissions are deliberate. The kernel maps pages lazily on a non-hardened process and does not re-verify them after load, so the hash reported at exec is not a reliable identity for the bytes that will eventually execute. An all-zero hash is the kernel saying it has none, and emitting it would let a rule whose identifier is forty zeros match by coincidence. A value that cannot be relied on is worse than an absent one.

The field is what lets an operator exclude a code-signed parent from a `suspicious_exec` finding by its non-spoofable code identity instead of a path glob an attacker who can write to a world-writable directory could land inside, so its absence where a hash does exist is a loss of that defence and not a cosmetic gap.

#### Scenario: A user runs a shell command

- **GIVEN** the endpoint event capture is running
- **WHEN** a user launches `/bin/ls` from a shell
- **THEN** the system emits an `exec` event whose payload includes the new image path, the argument vector, the parent PID, the effective UID and GID, and the code-signing identity (team ID, signing ID, platform-binary flag) when the binary is signed
- **AND** the payload includes the process's `pidversion` when its audit token is available
- **AND** the system later emits an `exit` event for the same PID with the process exit status

#### Scenario: A daemon forks a worker

- **GIVEN** the endpoint event capture is running
- **WHEN** a process calls `fork(2)` without a subsequent exec
- **THEN** the system emits a `fork` event whose payload identifies the parent PID and the child PID
- **AND** the payload includes the child process's `pidversion` when its audit token is available

#### Scenario: The exec event carries cdhash only when the kernel reported one

- **GIVEN** the endpoint event capture is running
- **WHEN** a process execs a binary that runs under Apple's Hardened Runtime and the kernel reports a hash for it
- **THEN** the `exec` event payload carries `cdhash`
- **AND** an exec of a binary that does not use the Hardened Runtime omits `cdhash`
- **AND** an exec whose reported hash is all zeros omits `cdhash` rather than carrying forty zeros
- **AND** the event is otherwise well-formed in every case

### Requirement: Launch-item registration event capture

The system SHALL emit a `btm_launch_item_add` event when launchd registers a launch item (a LaunchDaemon, LaunchAgent, or login item) via Background Task Management. The payload MUST carry the item type, the launch item path, the registered executable path when available, the MDM-managed flag, and the code-signing identity of the REGISTERED EXECUTABLE (`executable_code_signing`: team ID, signing ID, platform-binary flag) evaluated out-of-band, because the event provides code-signing for the instigator process but not for the to-be-launched executable.

#### Scenario: A LaunchDaemon is registered via Background Task Management

- **GIVEN** the endpoint event capture is running
- **WHEN** launchd registers a system LaunchDaemon (for example via `launchctl bootstrap`)
- **THEN** the system emits a `btm_launch_item_add` event whose payload includes `item_type=daemon`, the launch item path, the registered executable path, the MDM-managed flag, and the registered executable's code-signing identity

### Requirement: Sensitive-path file-modification capture

The system SHALL emit a write-mode `open` event when a process creates or writes a file under a fixed set of sensitive target paths (currently `/etc/sudoers` and any direct child of `/etc/sudoers.d/`), carrying the writing process PID, the file path, and write-mode access flags. The system SHALL NOT forward a broad stream of file opens: collection is scoped at the source to those sensitive target paths via a dedicated Endpoint Security client with inverted target-path muting, kept separate from the process-authorization client so the scoping never affects exec authorization (ADR-0008). Writes to paths outside the sensitive set MUST NOT be collected.

The system SHALL additionally emit a `file_rename` event when a process renames a file into, within, or out of that same sensitive set, carrying the renaming process PID, the source path, and the destination path. Both paths are required: a rename is the only operation in this set that makes a file become sudo policy without any write to the destination, and the source is what distinguishes a file promoted from a scratch path elsewhere from one already inside the watched directory.

Renames SHALL be collected under the same inverted target-path muting as creations and writes, which matches a rename when EITHER of its paths falls in the sensitive set.

#### Scenario: A write to a sensitive path is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process writes to `/etc/sudoers` (or a direct child of `/etc/sudoers.d/`)
- **THEN** a write-mode `open` event is emitted carrying the writing process PID, the file path, and the write-mode access flags
- **AND** the event reaches the server and is available to the detection pipeline

#### Scenario: A rename event carries both of its paths

- **GIVEN** a rename touching the sensitive set has been observed
- **WHEN** the extension serializes it
- **THEN** the `file_rename` event carries the renaming process PID, the source path, and the destination path
- **AND** the destination is carried under the same field name every other file event uses for its target, so one detection can read both

Note on verification: this scenario pins the event's SHAPE, which is what the extension's unit tests can reach. That the ESF client is subscribed and that `handleRename` reads both halves of the rename union are exercised at the system / VM layer per `docs/testing-strategy.md`, because `FileTamperSubscriber` imports EndpointSecurity and is outside the unit-testable target.

### Requirement: Outbound socket flow capture

The system SHALL emit a `network_connect` event for every outbound socket flow seen by the network filter, attributing the flow to the source process. Inbound flows SHALL be tagged with `direction = inbound`. The system MUST NOT block flows on the basis of capture; capture is observation-only. The `network_connect` payload SHALL additionally carry the source process's kernel PID generation (`pidversion`, read from the flow's audit token) when it is available, so the server can correlate the flow to the exact process generation. The `pidversion` field is optional: when the flow carries no usable audit token the event is still emitted without it.

#### Scenario: A process opens an outbound TCP connection

- **GIVEN** the network filter is enabled
- **WHEN** a process initiates an outbound TCP connection to a remote endpoint
- **THEN** the system emits a `network_connect` event whose payload identifies the source PID, the source binary path, the effective UID, the protocol (`tcp` or `udp`), the direction (`outbound`), the remote address, the remote port, the local address, the local port, and (when the system can derive it from the flow) the remote hostname
- **AND** the payload includes the source process's `pidversion` when the flow's audit token is available
- **AND** the flow is allowed to proceed unmodified

### Requirement: DNS query capture

When DNS proxying is enabled, the system SHALL emit a `dns_query` event for each DNS query seen by the DNS proxy and a follow-on `dns_query` event carrying the resolved addresses when the upstream resolver replies. DNS proxying is opt-in (see the host-app extension manager capability), so a host with the DNS proxy disabled emits no `dns_query` events at all and that absence is not a contract violation. The `dns_query` payload SHALL additionally carry the querying process's kernel PID generation (`pidversion`, read from the flow's audit token) when it is available. The `pidversion` field is optional: when the flow carries no usable audit token the event is still emitted without it. Capture failures MUST NOT prevent the query or its response from being forwarded to the originally-intended resolver.

Because an enabled DNS proxy is the sole resolver for every claimed flow, forwarding itself MUST be resilient: each upstream forward SHALL be bounded by a deadline, and on forward failure or deadline expiry for a query that no active enforcement policy blocks the proxy SHALL fail open by releasing the flow cleanly rather than leaving the client's resolution hung. The proxy MUST NOT pin a flow indefinitely waiting on an upstream that never answers. Telemetry remains strictly best-effort and never gates forwarding or the fail-open path. Health-driven recovery from sustained forwarding failure is specified by the network-response capability.

#### Scenario: An application resolves a hostname over UDP

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a UDP DNS query for a hostname
- **THEN** the system forwards the query unchanged to the originally-intended resolver
- **AND** the system emits a `dns_query` event identifying the source PID, source path, effective UID, query name, query type, and protocol (`udp`)
- **AND** the payload includes the source process's `pidversion` when the flow's audit token is available
- **AND** when the resolver replies with one or more addresses the system emits a follow-on `dns_query` event carrying the resolved addresses in `response_addresses`

#### Scenario: A DNS query that cannot be parsed is still forwarded

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a DNS query whose payload the proxy cannot parse for telemetry
- **THEN** the system forwards the query to the originally-intended resolver
- **AND** the system does not emit a `dns_query` event for the unparsed payload

#### Scenario: An upstream that never replies does not hang resolution forever

- **GIVEN** DNS proxying is enabled and no active enforcement policy blocks the query
- **WHEN** an application sends a DNS query and the upstream resolver does not answer within the forward deadline
- **THEN** the proxy releases the flow rather than holding it open indefinitely
- **AND** the client's resolution is free to proceed (retry or roll over to another resolver) instead of being pinned by the proxy
- **AND** any telemetry for the query is best-effort and its absence is not a contract violation

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

### Requirement: Reconciliation events are tagged

The system SHALL distinguish synthesized reconciliation events from kernel-observed events. Synthetic exit events emitted to close out processes whose kernel exit notification was missed SHALL carry `exit_reason = host_reconciled`, synthetic exec events emitted at startup to materialize processes that already existed before subscription SHALL carry `snapshot = true`, and liveness pings for those snapshot-originated processes SHALL be emitted as a distinct event type `snapshot_heartbeat` carrying only the process identifier in its payload.

#### Scenario: Agent fills a missing exit event

- **GIVEN** a process disappeared from the kernel without producing an exit event
- **WHEN** the reconciliation pass detects the absent process
- **THEN** the system emits an `exit` event for the missing PID with `exit_reason = host_reconciled`

#### Scenario: Extension restarts and rebuilds the live process set

- **GIVEN** the system extension has just started
- **WHEN** the system enumerates processes that already existed before subscription began
- **THEN** the system emits one `exec` event per such process with `snapshot = true`
- **AND** detection rules ignore those events because they describe historical state

#### Scenario: Snapshot-originated process is still alive on a later pass

- **GIVEN** a snapshot-originated process that the kernel still reports as live
- **WHEN** the reconciliation pass probes the process
- **THEN** the system emits a `snapshot_heartbeat` event whose payload identifies the process
- **AND** detection rules ignore those events because they describe liveness rather than activity

### Requirement: Capture is non-fatal on individual event errors

The system SHALL continue capturing subsequent events when serialization, attribution, or upstream forwarding of a single event fails. A single malformed event MUST NOT take the capture pipeline offline.

#### Scenario: One event fails to serialize

- **GIVEN** the capture pipeline is running
- **WHEN** a single event cannot be serialized into the canonical envelope
- **THEN** the system drops that one event
- **AND** the system continues capturing and emitting subsequent events

### Requirement: Serialized events declare their platform

The macOS system extension serializers SHALL stamp the platform that produced the event on every event envelope they emit. Because this extension runs only on macOS, the stamped value SHALL be `darwin`, matching the server's canonical platform constant. The field is part of the platform-aware event contract so the server can scope detection rules by platform and surface it in the host inventory.

#### Scenario: An ESF event envelope carries the darwin platform

- **GIVEN** the endpoint-security serializer encodes an event envelope
- **WHEN** the encoded JSON is inspected
- **THEN** its `platform` field is `darwin`

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

### Requirement: Destruction of a sensitive file is captured

The system SHALL emit a `file_truncate` event when a process discards the contents of a file in the sensitive target set, and a `file_delete` event when a process removes one, each carrying the acting process PID and the path.

Truncation SHALL be captured however it is performed. `truncate(2)` and `ftruncate(2)` are one kernel path and an `open(2)` carrying `O_TRUNC` is another, and only the second is what a shell redirect uses, so capturing either alone leaves the common case invisible.

An open that does NOT discard contents SHALL NOT be emitted. The sensitive paths are read routinely, since every `sudo` invocation reads the policy, so reporting those reads would turn a destruction signal into a stream of ordinary privilege checks. The filter belongs in the extension rather than in a rule, because what is being avoided is what reaches the wire at all.

Note on verification: the scenarios below pin the event SHAPES, which is what this repository's tests can reach. That the ESF client is subscribed to the three event types, that an `O_TRUNC` open is told from a routine read, and that a truncate syscall and a shell redirect both arrive are exercised at the system / VM layer per `docs/testing-strategy.md`, because `FileTamperSubscriber` imports EndpointSecurity and is outside the unit-testable target.

#### Scenario: An emptied file is reported as a truncation

- **GIVEN** a process has discarded the contents of a file in the sensitive set
- **WHEN** the extension serializes the event
- **THEN** a `file_truncate` event carries the acting process PID and the path
- **AND** the same shape is produced whether the contents were discarded by a truncate syscall or by an open carrying `O_TRUNC`

#### Scenario: A removed file is reported as a deletion

- **GIVEN** a process has removed a file in the sensitive set
- **WHEN** the extension serializes the event
- **THEN** a `file_delete` event carries the acting process PID and the path
- **AND** it is distinguishable from a truncation, because an emptied file still exists and a removed one does not
