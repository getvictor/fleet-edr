# agent-control-channel

## MODIFIED Requirements

### Requirement: The connection detects and recovers from silent failure

The agent SHALL keep the connection alive with periodic liveness probes and SHALL reconnect with backoff when the connection drops or a probe fails, so a network path that silently drops idle connections degrades to repeated reconnects rather than a host going dark.

A liveness probe passing MUST NOT be treated as proof that commands can be delivered. The probe is answered by the transport layer beneath the stream, which establishes that the network path is alive and not that the stream is still registered for delivery, so the two MUST NOT be conflated.

The server SHALL therefore send the agent a frame on a bounded cadence for as long as it holds the connection, carrying no payload: its arrival is the signal. The agent SHALL treat the absence of ANY frame for longer than a bounded deadline as proof that the connection is no longer being served, and SHALL tear it down and reconnect. The deadline MUST be measured against any frame rather than against command traffic, because an idle fleet is normal and a heartbeat is the only thing that distinguishes idle from forgotten.

#### Scenario: A half-open connection is detected and re-established

- **GIVEN** an agent holding a connection that a network path has silently dropped
- **WHEN** a liveness probe fails to complete
- **THEN** the agent treats the connection as lost and reconnects
- **AND** reconnect attempts back off rather than retrying in a tight loop

#### Scenario: An idle connection still carries proof that the server holds it

- **GIVEN** a connected host with no commands queued for it
- **WHEN** the server's heartbeat cadence elapses
- **THEN** the agent receives a frame carrying no command
- **AND** the connection is not torn down for being idle

#### Scenario: A connection the server no longer serves is torn down

- **GIVEN** an agent holding a connection the server has forgotten, whose underlying transport remains healthy
- **WHEN** no frame of any kind arrives for longer than the agent's deadline
- **THEN** the agent tears the connection down and reconnects, rather than waiting on it indefinitely
