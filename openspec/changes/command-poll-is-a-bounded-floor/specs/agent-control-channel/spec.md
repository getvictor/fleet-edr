# agent-control-channel

## MODIFIED Requirements

### Requirement: The connection detects and recovers from silent failure

The agent SHALL keep the connection alive with periodic liveness probes and SHALL reconnect with backoff when the connection drops or a probe fails, so a network path that silently drops idle connections degrades to repeated reconnects rather than a host going dark.

The agent MUST NOT let its own belief that the connection is healthy suppress the command poll indefinitely. The poll SHALL run at least once per bounded floor interval whatever the agent believes about its connection, so that a connection the agent holds but the server no longer recognizes degrades to slow polling rather than to silence.

Because both transports can now deliver the same command at once, the agent SHALL execute a command at most once across them and MUST NOT report a command failed on the grounds that another transport holds it. A durable execution claim cannot distinguish an attempt running elsewhere in the process from one left behind by a crash, so the agent SHALL track which commands it is currently executing and treat only a claim with no live attempt as interrupted.

A liveness probe passing MUST NOT be treated as proof that commands can be delivered. The probe can be answered by the transport layer beneath the stream, which establishes that the network path is alive and not that the stream is still registered for delivery, so the two must not be conflated.

#### Scenario: A half-open connection is detected and re-established

- **GIVEN** an agent holding a connection that a network path has silently dropped
- **WHEN** a liveness probe fails to complete
- **THEN** the agent treats the connection as lost and reconnects
- **AND** reconnect attempts back off rather than retrying in a tight loop

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
