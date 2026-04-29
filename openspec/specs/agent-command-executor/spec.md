# Agent Command Executor Specification

## Purpose

The agent command executor is the agent's response surface for operator-issued actions. The server queues per-host commands
in response to UI actions or policy updates; the agent polls for them, runs them locally, and reports an outcome the operator
can read in the UI. Without this capability, the platform would be a one-way telemetry pipe and operators would have no way
to terminate a malicious process or push a refreshed blocklist to a specific host.

The capability is deliberately authoritative on outcome reporting and conservative on dispatch. Commands are scoped to the
authenticated host so a token compromise on one host cannot drive actions on another, every command transitions through
explicit acknowledged-then-completed-or-failed states so the operator audit trail is always conclusive, and unknown command
types or missing dispatch dependencies fail with a clear reason rather than silently accepting and discarding the command.

## Requirements

### Requirement: Commands are scoped to the authenticated host

The system SHALL return only the commands queued for the host whose bearer token authenticated the poll, regardless of any
host identifier the agent includes in the request.

#### Scenario: Polling returns only this host's commands

- **GIVEN** the server has pending commands for hosts A and B
- **WHEN** host A polls the commands endpoint with its own token
- **THEN** the response contains only commands whose host identifier is A
- **AND** the response never contains commands belonging to host B

#### Scenario: Token does not match query host

- **GIVEN** host A authenticates with its token but includes B in the host query parameter
- **WHEN** the agent polls the commands endpoint
- **THEN** the response is scoped to A, the authenticated host, not to B

### Requirement: Polling cadence is configurable

The system SHALL poll the server at a configured interval and SHALL handle context cancellation between polls without
discarding the current poll's response.

#### Scenario: Configured interval is honored

- **GIVEN** the executor is configured with a poll interval
- **WHEN** the executor runs
- **THEN** consecutive polls are separated by approximately the configured interval
- **AND** poll requests do not overlap

#### Scenario: Cancellation between polls

- **GIVEN** the executor is idling between polls
- **WHEN** the agent's context is cancelled
- **THEN** the executor stops cleanly
- **AND** any in-flight command currently being executed completes its status report if possible

### Requirement: Command lifecycle is explicit

The system MUST move each command through a server-visible acknowledged state before execution and through either completed
or failed after execution, so an operator viewing the UI never sees a stuck pending command after the agent has begun work.

#### Scenario: Successful command transitions

- **GIVEN** the executor receives a pending command from the poll response
- **WHEN** the executor begins executing it
- **THEN** the executor first reports an acknowledged status to the server
- **AND** after execution it reports either completed (with a result payload) or failed (with an error reason)

#### Scenario: Acknowledgement fails

- **GIVEN** the executor cannot reach the server to report acknowledged status
- **WHEN** the acknowledgement attempt fails
- **THEN** the executor does not execute the command's side effects
- **AND** the command remains eligible for re-dispatch on the next poll

### Requirement: Process-termination command

The system SHALL execute a kill-process command by sending SIGKILL to the requested process identifier on the local host and
SHALL report a structured outcome distinguishing success from "no such process" and from permission denied.

#### Scenario: Successful kill

- **GIVEN** a kill-process command is received with a live process identifier
- **WHEN** the agent sends SIGKILL to that process identifier
- **THEN** the executor reports completed with a result identifying the killed process identifier

#### Scenario: Process is already gone

- **GIVEN** a kill-process command is received but the process has already exited
- **WHEN** the agent attempts to signal it
- **THEN** the executor reports failed with an error reason that conveys "no such process"

#### Scenario: Process identifier is non-positive

- **GIVEN** a kill-process command is received with a zero or negative process identifier
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed without sending any signal to the kernel
- **AND** the failure reason identifies the invalid input

### Requirement: Set-blocklist command

The system SHALL execute a set-blocklist command by forwarding the policy payload to the local endpoint security extension
and SHALL report the policy version that was forwarded so operators can confirm convergence per host.

#### Scenario: Forwarded successfully

- **GIVEN** a set-blocklist command is received with a positive version and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the executor reports completed with the policy version and the count of paths in the payload

#### Scenario: Extension bridge is not available

- **GIVEN** the agent has no configured extension bridge
- **WHEN** a set-blocklist command is received
- **THEN** the executor reports failed with a reason identifying the missing bridge
- **AND** no SIGKILL or other side effect is performed

#### Scenario: Payload is missing required fields or has a non-positive version

- **GIVEN** a set-blocklist command is received whose payload is malformed or whose version is zero or negative
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid payload
- **AND** the extension bridge is not invoked

### Requirement: Unknown command types fail explicitly

The system SHALL reject command types it does not implement by reporting failed with a reason identifying the unknown type,
rather than acknowledging or silently dropping them.

#### Scenario: Unknown command type

- **GIVEN** the server queues a command whose type the agent does not recognize
- **WHEN** the agent dispatches it
- **THEN** the executor reports failed with a reason identifying the unknown command type
- **AND** no host-side side effect is performed

### Requirement: 401 during command flow triggers re-enrollment

The system MUST signal the enrollment subsystem when the server returns 401 on either a poll or a status report so the agent
can refresh its host token without operator intervention.

#### Scenario: 401 on poll

- **GIVEN** the executor is polling for commands
- **WHEN** the server returns 401
- **THEN** the executor invokes the registered authentication-failure callback
- **AND** the executor does not treat the 401 as a permanent failure for the next cycle

#### Scenario: 401 on status update

- **GIVEN** the executor is reporting an acknowledged or completed status
- **WHEN** the server returns 401
- **THEN** the executor invokes the registered authentication-failure callback
- **AND** the same status update remains the executor's responsibility on the next cycle

