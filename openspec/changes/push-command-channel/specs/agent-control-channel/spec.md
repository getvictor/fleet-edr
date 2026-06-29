## ADDED Requirements

### Requirement: The agent holds a persistent authenticated control connection

The agent SHALL maintain a single persistent control connection to the server, authenticated once at connect time with the host's bearer token rather than with a per-message credential, over a server-authenticated transport with the same leaf-certificate pinning the agent applies to its other server calls. The server SHALL accept the connection only when the presented host token verifies (valid signature, not expired, not revoked) and SHALL reject it otherwise without opening the channel.

#### Scenario: Connection opens with a valid host token

- **GIVEN** an enrolled host with a currently-valid host token
- **WHEN** the agent opens the control connection presenting that token at connect
- **THEN** the server verifies the token locally without a database lookup and accepts the connection
- **AND** the server associates the connection with the host identifier carried in the token

#### Scenario: Connection is refused for an invalid or expired token

- **GIVEN** a host presenting an absent, malformed, or expired token at connect
- **WHEN** the agent attempts to open the control connection
- **THEN** the server refuses to open the channel
- **AND** no command is delivered over the refused connection

### Requirement: Queued commands are delivered over the connection in real time

The system SHALL deliver a command queued for a connected host over that host's open connection without waiting for a poll cycle. A command queued on the replica that holds the host's connection SHALL be delivered immediately; a command queued on a different replica SHALL be delivered within a bounded command-watch interval. Command-delivery latency is therefore bounded by the server's command-watch latency, not by an agent poll interval.

#### Scenario: Command queued for a connected host is pushed promptly

- **GIVEN** a host holding an open control connection
- **WHEN** an operator action queues a command for that host
- **THEN** the server pushes the command over the host's connection without the host issuing a poll

#### Scenario: Command queued on the connection-holding replica is delivered immediately

- **GIVEN** a host whose connection is held by the same replica that queues a command for it
- **WHEN** the command is queued
- **THEN** the server delivers it over the connection immediately, without waiting for the command-watch interval

#### Scenario: Command queued on another replica is delivered within the watch interval

- **GIVEN** a host whose connection is held by one replica while a command for it is queued on a different replica
- **WHEN** the command is queued
- **THEN** the holding replica delivers it over the connection within at most the bounded command-watch interval

### Requirement: Command outcomes are reported over the same connection with the same lifecycle

The system SHALL carry command acknowledgement and the completed-or-failed outcome over the same connection, advancing each command through the same acknowledged-then-completed-or-failed lifecycle and the same server-side state-transition rules as the polled path, so the operator audit trail is identical regardless of which transport delivered the command.

#### Scenario: Acknowledge then complete over the connection

- **GIVEN** a command delivered over the connection
- **WHEN** the agent begins executing it and then finishes
- **THEN** the agent first reports acknowledged over the connection, then reports completed with a result or failed with a reason
- **AND** the command's recorded status transitions are identical to those of a command handled over the poll path

### Requirement: Delivery is at-least-once and idempotent by command identity

The system MAY offer the same command over a connection more than once, and SHALL ensure a command is executed at most once: the agent SHALL treat a re-delivered command whose lifecycle has already advanced past pending as already handled and SHALL NOT repeat its side effect, and the server SHALL reject an outcome report that does not represent a valid status transition.

#### Scenario: The same command delivered twice executes once

- **GIVEN** a command that has already been delivered, acknowledged, and executed on a host
- **WHEN** the same command is delivered to that host's connection again
- **THEN** the agent does not repeat the command's side effect
- **AND** an acknowledgement for the already-advanced command is rejected as an invalid transition rather than recorded

### Requirement: Commands on the connection are scoped to the authenticated host

The system SHALL deliver over a connection only commands queued for the host whose token authenticated that connection, and SHALL reject an outcome report for a command that does not belong to that host, so a token compromise on one host cannot drive or observe actions on another.

#### Scenario: A connection never receives another host's commands

- **GIVEN** pending commands for hosts A and B, and host A holding a connection
- **WHEN** the server pushes commands to host A's connection
- **THEN** host A receives only commands whose host identifier is A
- **AND** host A never receives a command belonging to host B

#### Scenario: An outcome report for another host's command is rejected

- **GIVEN** host A's connection authenticated as host A
- **WHEN** an outcome frame on that connection references a command belonging to host B
- **THEN** the server rejects the report and the command belonging to B is unchanged

### Requirement: Connection presence is authoritative host liveness

While a host holds an open control connection the system SHALL treat the host as online and SHALL advance its last-seen time without requiring a telemetry upload or a command poll; on disconnect the host's online status SHALL reflect the lost connection.

#### Scenario: A connected host's last-seen advances without polling

- **GIVEN** a host holding an open control connection and issuing neither uploads nor command polls
- **WHEN** time passes while the connection stays open
- **THEN** the host's last-seen time advances on the connection's keep-alive cadence
- **AND** the host is reported online

#### Scenario: Disconnect reflects in online status

- **GIVEN** a host reported online via its open connection
- **WHEN** the connection drops
- **THEN** the host's online status reflects the lost connection

### Requirement: The connection detects and recovers from silent failure

The agent SHALL keep the connection alive with periodic liveness probes and SHALL reconnect with backoff when the connection drops or a probe fails, so a network path that silently drops idle connections degrades to repeated reconnects rather than a host going dark.

#### Scenario: A half-open connection is detected and re-established

- **GIVEN** an agent holding a connection that a network path has silently dropped
- **WHEN** a liveness probe fails to complete
- **THEN** the agent treats the connection as lost and reconnects
- **AND** reconnect attempts back off rather than retrying in a tight loop

### Requirement: A revoked or expired token terminates the connection

The system SHALL close a control connection whose host token has been revoked or has expired, within the revocation-propagation bound, so a deauthorized host cannot retain a live control channel. The agent SHALL be required to re-authenticate with a currently-valid token to reconnect.

#### Scenario: Revoking a token closes the connection

- **GIVEN** a host holding an open connection whose token is then revoked
- **WHEN** the revocation propagates within its bound
- **THEN** the server closes that host's connection
- **AND** a reconnect attempt with the revoked token is refused
