# agent-control-channel Specification

## Purpose

The agent holds a single persistent, host-token-authenticated control connection to the server over the existing HTTPS listener, so the server can push commands (isolate, kill, and future actions) with sub-second latency. The connection is derived from the configured server URL with no separate address or enabling flag, and the `GET /api/commands` short-poll remains the fallback floor whenever the stream is unavailable.

## Requirements

### Requirement: The agent derives the control endpoint from its server URL

The agent SHALL derive the control-channel endpoint from its configured server URL, dialing the same host and port it uses for the REST API, over the same transport security: the pinned-TLS configuration for an `https` server URL, and cleartext for an `http` server URL (the development / proxy-terminated posture). The agent SHALL NOT require a separate control-channel address. The agent SHALL attempt the control channel whenever a server URL and a host identity are configured, without a separate enabling flag; when the stream cannot be established or is lost, the agent SHALL continue to serve commands over the `GET /api/commands` short-poll, which remains the fallback floor.

#### Scenario: The control endpoint is derived from the server URL

- **GIVEN** an agent configured with a server URL and no separate control-channel address
- **WHEN** it opens the control channel
- **THEN** it dials the same host and port as the server URL, with the same transport security
- **AND** an `https` URL dials with the agent's pinned-TLS configuration while an `http` URL dials cleartext

### Requirement: The agent holds a persistent authenticated control connection

The agent SHALL maintain a single persistent control connection to the server, authenticated once at connect time with the host's bearer token rather than with a per-message credential, over a server-authenticated transport with the same leaf-certificate pinning the agent applies to its other server calls. The server SHALL accept the connection only when the presented host token verifies (valid signature, not expired, not revoked) and SHALL reject it otherwise without opening the channel. The server SHALL hold at most one connection per host: when a new connection is accepted for a host that already has one, the server SHALL close and release the prior connection and treat the new one as the sole authoritative channel for that host.

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

#### Scenario: A reconnect replaces the prior connection for the same host

- **GIVEN** a host holding an open control connection that then reconnects (for example after a token refresh) before the old connection is observed as closed
- **WHEN** the server accepts the new connection
- **THEN** the server closes and releases the prior connection for that host
- **AND** only the new connection receives subsequent pushes, with no leaked prior connection

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

The system MAY offer the same command over a connection more than once, and SHALL run a command's side effect at most once. The agent SHALL key execution by command identity and SHALL record each command's final outcome; on re-delivery of a command it has already executed, the agent SHALL re-report the recorded outcome rather than repeating the side effect, so a command whose outcome report was lost still transitions out of pending rather than being silently dropped and left stuck. The server SHALL reject an outcome report that is not a valid transition for the command's current status, which the agent treats as already handled.

#### Scenario: A re-delivered command re-reports its recorded outcome without repeating the side effect

- **GIVEN** a command that a host already executed but whose outcome report was lost, so the command is still pending on the server
- **WHEN** the command is delivered to that host's connection again
- **THEN** the agent does not repeat the command's side effect
- **AND** the agent re-reports the recorded outcome so the server transitions the command out of pending

#### Scenario: An outcome that is not a valid transition is rejected

- **GIVEN** a command whose status has already advanced past the reported transition
- **WHEN** the agent reports an outcome that the current status does not permit
- **THEN** the server rejects it rather than recording it
- **AND** the agent treats the rejection as already handled, not as a failure

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

A liveness probe passing MUST NOT be treated as proof that commands can be delivered. The probe is answered by the transport layer beneath the stream, which establishes that the network path is alive and not that the stream is still registered for delivery, so the two MUST NOT be conflated.

The server SHALL therefore send the agent a frame on a bounded cadence for as long as it holds the connection, carrying no payload: its arrival is the signal. The agent SHALL treat the absence of ANY frame for longer than a bounded deadline as proof that the connection is no longer being served, and SHALL tear it down and reconnect. The deadline MUST be measured against any frame rather than against command traffic, because an idle fleet is normal and a heartbeat is the only thing that distinguishes idle from forgotten.

The heartbeat MUST NOT depend on any datastore. Once agents tear a stream down on silence, a stalled write on the path that produces the heartbeat would stop heartbeats for every connected host at once and turn a datastore incident into a fleet-wide reconnect storm against the same server. Any datastore work sharing that path SHALL be bounded well below the agent's silence deadline.

The agent MUST NOT let its own belief that the connection is healthy suppress the command poll indefinitely. The poll SHALL run at least once per bounded floor interval whatever the agent believes about its connection, so that a connection the agent holds but the server no longer recognizes degrades to slow polling rather than to silence.

Because both transports can now deliver the same command at once, the agent SHALL execute a command at most once across them and MUST NOT report a command failed on the grounds that another transport holds it. A durable execution claim cannot distinguish an attempt running elsewhere in the process from one left behind by a crash, so the agent SHALL track which commands it is currently executing and treat only a claim with no live attempt as interrupted.

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

#### Scenario: A stalled datastore does not stop heartbeats

- **GIVEN** a connected host and a datastore that has stopped answering the periodic host-liveness write
- **WHEN** the heartbeat cadence elapses
- **THEN** the agent still receives its heartbeat promptly, and the connection is not torn down

#### Scenario: A connection the server has forgotten does not silence commands

- **GIVEN** an agent holding a connection that the server no longer recognizes for delivery, which the agent still believes is healthy
- **WHEN** a command is queued for that host and the floor interval elapses
- **THEN** the agent polls for pending commands despite believing its connection is up
- **AND** the queued command is delivered and executed, so the outage is a bounded delay rather than permanent deafness

#### Scenario: A healthy connection still owns delivery

- **GIVEN** an agent holding a connection that is genuinely delivering commands
- **WHEN** commands arrive within the floor interval
- **THEN** the agent does not poll, so the steady state remains push-driven

#### Scenario: Both transports deliver one command at the same time

- **GIVEN** an agent whose push transport and floor poll both receive the same queued command
- **WHEN** they attempt it concurrently
- **THEN** the command is executed once, and reported once through its acknowledged-then-terminal lifecycle
- **AND** neither transport reports it failed on account of the other holding it

#### Scenario: An execution claim left by a crash is still resolved

- **GIVEN** an execution claim recorded by a previous run of the agent that did not complete
- **WHEN** the command is delivered again after restart
- **THEN** the agent terminalizes it rather than re-running the side effect, because no live attempt holds it

### Requirement: A revoked or expired token terminates the connection

The system SHALL close a control connection whose host token has been revoked or has expired, within the revocation-propagation bound, so a deauthorized host cannot retain a live control channel. The agent SHALL be required to re-authenticate with a currently-valid token to reconnect.

#### Scenario: Revoking a token closes the connection

- **GIVEN** a host holding an open connection whose token is then revoked
- **WHEN** the revocation propagates within its bound
- **THEN** the server closes that host's connection
- **AND** a reconnect attempt with the revoked token is refused

### Requirement: A queued command can be withdrawn, and ages out rather than being delivered late

The system SHALL provide an operator path to withdraw a command that no agent has picked up, and SHALL record it in a state distinct from a command an agent attempted and could not complete. An operator auditing a host has to be able to tell "nothing ran" from "something ran and went wrong", and collapsing the two into one state destroys that distinction permanently.

The system SHALL age out a command that has waited for delivery beyond a bounded window, rather than delivering it once the host becomes reachable again. This is a safety property rather than tidiness: a process-termination command addresses a process by PID, PIDs are reused, and a command delivered long after it was issued can terminate an unrelated process on that host.

Withdrawal is a request that wins only if no agent had already taken the command, and MUST NOT be treated as a guarantee that it never runs. Delivery and withdrawal race: a command is pushed while its record still says pending, and the agent begins the side effect and acknowledges asynchronously, so a withdrawal can land before that acknowledgement is recorded. When an acknowledgement arrives for a command already recorded as withdrawn or aged out, the system SHALL accept it and let the record follow what actually happened on the host. Leaving those states closed would record that nothing ran for a command that did run, which is the misreport this requirement exists to prevent.

Withdrawal and ageing out SHALL both be reachable only from the pending state. Once an agent has acknowledged a command it owns it and may already have applied the side effect, so recording either outcome would misreport what happened on the host.

Withdrawing a command SHALL require the same authority as issuing that kind of command, and MUST NOT be permitted on read access alone. Preventing a response action is itself a response decision, and an actor who could withdraw commands on a host they can only observe could disable incident response there.

#### Scenario: An operator withdraws a command no agent has taken

- **GIVEN** a command queued for a host that has not acknowledged it
- **WHEN** an operator with authority to issue that kind of command withdraws it
- **THEN** the command is recorded in a state that says no agent ran it, distinct from having been attempted and failed
- **AND** it is no longer offered to that host for delivery

#### Scenario: Withdrawal is refused once the agent has the command

- **GIVEN** a command a host has already acknowledged
- **WHEN** an operator attempts to withdraw it
- **THEN** the request is refused and the command's recorded state is unchanged, because the side effect may already have been applied

#### Scenario: A command that waited too long is aged out instead of delivered

- **GIVEN** a command that has been queued for longer than the delivery window, for a host that then asks for its pending work
- **WHEN** the system answers that request
- **THEN** the aged-out command is not among the commands delivered
- **AND** it is recorded as having expired, so an operator can see why it never ran

#### Scenario: Ageing out does not disturb a command the agent already owns

- **GIVEN** a command a host acknowledged before the delivery window elapsed
- **WHEN** the delivery window passes
- **THEN** the command's recorded state is unchanged, because the agent may have applied it

#### Scenario: A late acknowledgement corrects a withdrawn command

- **GIVEN** a command an operator withdrew after it had already been delivered to the host
- **WHEN** the agent's acknowledgement and outcome arrive afterwards
- **THEN** they are accepted and the record reports what ran on the host, rather than continuing to report that nothing did
