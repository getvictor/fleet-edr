# Endpoint event collection: carry audit-token pidversion on process and flow events delta

## MODIFIED Requirements

### Requirement: Process lifecycle event capture

The system SHALL emit a `fork` event when a monitored process forks, an `exec` event when a process replaces its image, and an `exit` event when a process exits. Each event MUST carry the originating PID and any additional fields documented for that event type. The `exec` event SHALL additionally carry the process's own kernel PID generation and the `fork` event SHALL carry the child process's kernel PID generation (`pidversion`, read from the respective process's audit token) when it is available, so the server can disambiguate reused PIDs by identity rather than by time. The `pidversion` field is optional: when the audit token is unavailable the event is still emitted without it.

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
