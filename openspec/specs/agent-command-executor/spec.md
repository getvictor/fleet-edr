# Agent Command Executor Specification

## Purpose

The agent command executor is the agent's response surface for operator-issued actions. The server queues per-host commands in response to UI actions or policy updates; the agent polls for them, runs them locally, and reports an outcome the operator can read in the UI. Without this capability, the platform would be a one-way telemetry pipe and operators would have no way to terminate a malicious process or push a refreshed blocklist to a specific host.

The capability is deliberately authoritative on outcome reporting and conservative on dispatch. Commands are scoped to the authenticated host so a token compromise on one host cannot drive actions on another, every command transitions through explicit acknowledged-then-completed-or-failed states so the operator audit trail is always conclusive, and unknown command types or missing dispatch dependencies fail with a clear reason rather than silently accepting and discarding the command.

## Requirements

### Requirement: Commands are scoped to the authenticated host

The system SHALL return only the commands queued for the host whose bearer token authenticated the poll, regardless of any host identifier the agent includes in the request.

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

The system SHALL poll the server at a configured interval and SHALL handle context cancellation between polls without discarding the current poll's response.

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

The system MUST move each command through a server-visible acknowledged state before execution and through either completed or failed after execution, so an operator viewing the UI never sees a stuck pending command after the agent has begun work.

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

The system SHALL execute a kill-process command by terminating the requested process identifier on the local host using the platform's native process-termination primitive (SIGKILL on Unix-like platforms, TerminateProcess on Windows) and SHALL report a structured outcome distinguishing success from "no such process" and from permission denied.

The kill-process command MAY carry the kernel process generation (`pidversion`) the operator selected. When it does AND the agent tracks the target process identifier's current live generation, the agent SHALL refuse the termination and report a structured failure, sending no signal to the kernel, if the tracked generation differs from the one carried on the command (the process identifier was reused or re-exec'd between selection and execution). When the command carries no generation, or the agent does not track that process identifier's generation (never observed, already exited, or lost across an agent restart), the agent SHALL proceed with the pid-only termination. The generation check therefore only ever strengthens the pid-only behavior: it never refuses a termination that would otherwise have succeeded.

The agent's knowledge of a process identifier's live generation is derived from the endpoint event stream (exec and fork establish a generation, exit clears it); it is a per-replica in-memory cache that is safe to lose, so a cold or lossy cache degrades to pid-only termination rather than blocking.

#### Scenario: Successful kill

- **GIVEN** a kill-process command is received with a live process identifier
- **WHEN** the agent terminates that process identifier
- **THEN** the executor reports completed with a result identifying the killed process identifier

#### Scenario: Process is already gone

- **GIVEN** a kill-process command is received but the process has already exited
- **WHEN** the agent attempts to terminate it
- **THEN** the executor reports failed with an error reason that conveys "no such process"

#### Scenario: Process identifier is non-positive

- **GIVEN** a kill-process command is received with a zero or negative process identifier
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed without sending any signal to the kernel
- **AND** the failure reason identifies the invalid input

#### Scenario: Kill is refused when the target generation no longer matches

- **GIVEN** a kill-process command carrying a process identifier and a selected generation
- **AND** the agent tracks that process identifier at a different live generation (the identifier was reused or re-exec'd)
- **WHEN** the executor evaluates the command
- **THEN** the executor reports failed with a reason identifying a process-generation mismatch
- **AND** no signal is sent to the kernel

#### Scenario: Kill proceeds when the selected generation still matches

- **GIVEN** a kill-process command carrying a process identifier and a selected generation
- **AND** the agent tracks that process identifier at the same live generation
- **WHEN** the executor evaluates the command
- **THEN** the agent terminates the process identifier and reports completed

#### Scenario: Kill falls back to pid-only when the generation is unsupplied or untracked

- **GIVEN** a kill-process command whose payload carries no generation, or whose process identifier the agent does not currently track
- **WHEN** the executor evaluates the command
- **THEN** the agent terminates the process identifier by identifier alone, as it did before generation pinning

### Requirement: Set-application-control command

The system SHALL execute a `set_application_control` command by forwarding the typed rule snapshot to the local Endpoint Security extension and SHALL report the policy identifier and version that were forwarded so the server can confirm per-host convergence. The payload SHALL carry `{policy_id, policy_version, rules}` where each `rules` entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url, severity}`. The executor SHALL validate that `policy_id` is non-empty and `policy_version` is positive before forwarding.

#### Scenario: Forwarded successfully

- **GIVEN** a `set_application_control` command is received with a non-empty `policy_id`, a positive `policy_version`, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the executor reports completed with the policy identifier, the policy version, and the count of rules in the payload

#### Scenario: Extension bridge is not available

- **GIVEN** the agent has no configured extension bridge
- **WHEN** a `set_application_control` command is received
- **THEN** the executor reports failed with a reason identifying the missing bridge
- **AND** no other side effect is performed

#### Scenario: Payload is missing required fields or has a non-positive version

- **GIVEN** a `set_application_control` command is received whose payload is missing `policy_id`, missing `policy_version`, or whose `policy_version` is zero or negative
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid payload
- **AND** the extension bridge is not invoked

#### Scenario: A rules entry has an unknown rule type

- **GIVEN** a `set_application_control` payload whose `rules` array contains a `rule_type` not in `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the unknown rule type
- **AND** the extension bridge is not invoked

### Requirement: Unknown command types fail explicitly

The system SHALL reject command types it does not implement by reporting failed with a reason identifying the unknown type, rather than acknowledging or silently dropping them.

#### Scenario: Unknown command type

- **GIVEN** the server queues a command whose type the agent does not recognize
- **WHEN** the agent dispatches it
- **THEN** the executor reports failed with a reason identifying the unknown command type
- **AND** no host-side side effect is performed

### Requirement: 401 during command flow triggers re-enrollment

The system MUST signal the enrollment subsystem when the server returns 401 on either a poll or a status report so the agent can refresh its host token without operator intervention.

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

### Requirement: Command execution is deduplicated durably across transports and restarts

The agent SHALL key command execution on a durable, per-agent ledger so a command's side effect runs at most once across BOTH the push (control connection) and poll transports and across agent restarts. Before running a command's side effect the agent SHALL record a write-ahead claim for the command id; after the side effect it SHALL record the terminal outcome. On encountering a command id that the ledger already records, the agent SHALL NOT re-run the side effect: if a terminal outcome is recorded it re-reports that outcome, and if only a write-ahead claim is recorded (a prior attempt that did not complete, for example an interrupted process) it reports the command failed rather than re-running the side effect, so a non-idempotent command such as `kill_process` never signals a since-reused PID on re-delivery.

#### Scenario: A command executed on one transport is not re-executed by the other

- **GIVEN** a command whose side effect the agent has already run and recorded a terminal outcome for (over the control connection)
- **WHEN** the same command id is delivered again on the poll path after the connection drops
- **THEN** the agent does not run the side effect again
- **AND** it re-reports the recorded terminal outcome, so the command's status stays stable rather than flipping

#### Scenario: A recorded outcome survives an agent restart

- **GIVEN** a command whose terminal outcome the agent recorded before it stopped
- **WHEN** the agent restarts and the same command id is delivered again
- **THEN** the recorded outcome is still available from the durable ledger
- **AND** the agent re-reports it without re-running the side effect

#### Scenario: Concurrent delivery of the same command runs the side effect once

- **GIVEN** the same command delivered on both transports at the same time
- **WHEN** the agent attempts to execute it from both
- **THEN** the write-ahead claim is recorded atomically, so exactly one execution wins the claim
- **AND** the side effect runs at most once; the other execution does not re-run it

### Requirement: The control connection is preferred and polling is the degraded floor

The system SHALL prefer the persistent control connection for command delivery and outcome reporting when it is established, and SHALL fall back to the polled command path only when the connection cannot be established or has dropped, so a host is never left without a command path. The polled cadence, lifecycle, and host-scoping are unchanged on the fallback path, and no additional fallback transport is introduced.

#### Scenario: Commands flow over the connection when it is up

- **GIVEN** a host holding an open control connection
- **WHEN** a command is queued for the host
- **THEN** the command is delivered and its outcome reported over the connection
- **AND** the agent does not depend on the command poll to receive or report it

#### Scenario: The poll is the fallback when the connection is unavailable

- **GIVEN** a host that cannot establish or has lost its control connection
- **WHEN** a command is queued for the host
- **THEN** the agent receives it on the polled command path at the configured interval
- **AND** acknowledges and completes it through the unchanged polled lifecycle
