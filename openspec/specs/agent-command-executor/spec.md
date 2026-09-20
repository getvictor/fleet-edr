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

The system SHALL execute a `set_application_control` command by forwarding the typed rule snapshot to the local Endpoint Security extension and SHALL report the policy identifier, the policy version, and the number of rules forwarded, so the server can confirm per-host convergence: the version says which policy the host took and the count says how much of it.

The payload SHALL carry `{policy_id, policy_version, policy_epoch, deadline_fallback, rules}`, where each `rules` entry carries `{rule_id, rule_type, identifier, action, enforcement, severity}` and MAY carry `custom_msg` and `custom_url`, which are omitted when unset. `policy_epoch` is the policy's server-assigned update time and is the restore-surviving companion to `policy_version`, so a server restore that regresses the version still re-syncs hosts. `deadline_fallback` governs the extension's verdict when a BINARY rule's hash cannot be computed inside the kernel deadline. Both are forwarded rather than interpreted: they are addressed to the extension, and the agent is a conduit for them.

The executor SHALL validate, before forwarding, that `policy_id` is a positive integer, that `policy_version` is a positive integer, and that `rules` is a JSON array. It SHALL NOT validate anything else in the payload, including the shape of the individual entries and the two fields addressed to the extension: the extension owns the rule shape, and the agent forwards the raw payload bytes so the wire shape stays byte-identical across server, agent, and extension.

#### Scenario: Forwarded successfully

- **GIVEN** a `set_application_control` command is received with a positive `policy_id`, a positive `policy_version`, a `rules` array, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the executor reports completed with the policy identifier, the policy version, and the count of rules in the payload

#### Scenario: Extension bridge is not available

- **GIVEN** the agent has no configured extension bridge
- **WHEN** a `set_application_control` command is received
- **THEN** the executor reports failed with a reason identifying the missing bridge
- **AND** no other side effect is performed

#### Scenario: Forwarding to the extension fails

- **GIVEN** a valid `set_application_control` payload and a configured extension bridge
- **WHEN** the transport to the extension returns an error
- **THEN** the executor reports failed with a reason carrying the transport error
- **AND** the reason is distinguishable from the missing-bridge reason, so an operator reading the audit trail can tell an absent extension from one that refused the payload

#### Scenario: Payload is missing required fields or carries a non-positive value

- **GIVEN** a `set_application_control` command is received whose payload has a `policy_id` or a `policy_version` that is absent, zero, or negative, or whose `rules` is absent or is not a JSON array
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid payload
- **AND** the extension bridge is not invoked

An entry whose `rule_type` the executor does not recognise SHALL NOT fail the payload. The executor SHALL forward the snapshot, and the extension SHALL apply the entries it understands and skip the rest.

Rejecting the whole payload was specified and is wrong, which is why this says so rather than leaving the requirement silent. `rule_type` is already validated by the server when the rule is created, so the case only arises where the agent is OLDER than the server that wrote the policy. Failing there converts an additive server change into a loss of application control on every host still running the previous agent: no rules apply, rather than the rules that agent understands. Partial enforcement with a warning is the better failure, and it is what the extension already does.

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

An outcome that did not reach the server SHALL be recoverable on the polled path as well as over the connection. The agent SHALL ask for the commands the server has acknowledged from this host and is still awaiting an outcome for, and SHALL re-report what its own ledger records for each, running no side effect. A command the ledger has no record of SHALL be left as it stands: the ledger may have been pruned or replaced, and an agent cannot tell that from a command it never ran, so reporting an outcome would invent one and running the command would repeat a side effect that was asked for once. This question MAY run on a longer interval than the poll for new work, since an outcome is already durable on the host and the answer is empty in the ordinary case.

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

#### Scenario: A lost outcome is recovered by polling

- **GIVEN** a host on the polled path whose command ran and whose outcome report did not reach the server
- **WHEN** the agent next asks about the commands awaiting an outcome
- **THEN** it re-reports the outcome its ledger recorded, and does not run the side effect again

#### Scenario: An unrecorded command is left alone

- **GIVEN** a command the server is awaiting an outcome for, and an agent whose ledger has no record of it
- **WHEN** the agent asks about the commands awaiting an outcome
- **THEN** it reports nothing for that command and runs nothing, and the command keeps the status it has

### Requirement: Set-network-containment command

The agent SHALL execute a `set_network_containment` command, whose payload carries `version`, `epoch` and `contained`, by sending the network extension a `network_containment.update` carrying those fields and, for a containment, the lifeline: the port of the endpoint the agent reaches the server through (the server, or the proxy for its URL), the addresses that endpoint resolves to, and its host name when it is not an IP literal. The agent SHALL resolve the lifeline by querying the configured resolvers directly, since the system resolver answers nothing on a contained host. The command SHALL complete only once the network extension reports that state applied, with a result naming the version, whether the host is contained, and the lifeline addresses. Commands SHALL run one at a time, so each confirmation is matched to the command that sent it. It SHALL fail, with the reason in its result, when the payload has no positive version or no `contained`, when the lifeline cannot be resolved (in which case nothing is sent), when the extension cannot be reached, when the extension reports the state not applied with an error or does not confirm within 15 seconds (a not-applied status with no error is pending, and the agent keeps waiting), when the extension reports the other `contained` value at the command's version, when the extension reports a newer state, and on a host without the network extension.

#### Scenario: The extension confirms the containment

- **GIVEN** an agent connected to the network extension
- **WHEN** it executes `set_network_containment` with `contained` true
- **THEN** it sends the extension the command's version and epoch with the resolved lifeline
- **AND** the command completes once the extension reports that version applied

#### Scenario: A containment whose lifeline cannot be resolved is not sent

- **GIVEN** an agent that cannot resolve the endpoint it reaches the server through
- **WHEN** it executes `set_network_containment` with `contained` true
- **THEN** it sends nothing to the extension and the command fails with the resolution error

#### Scenario: The extension does not apply the containment

- **GIVEN** an agent connected to the network extension
- **WHEN** the extension reports the command's state not applied with an error, the other `contained` value at the command's version, or a newer state, or reports nothing in time
- **THEN** the command fails with that reason

#### Scenario: A host without the network extension cannot contain

- **GIVEN** an agent with no network extension to contain with
- **WHEN** it executes `set_network_containment`
- **THEN** the command fails as not supported on the host

### Requirement: The server is reached through the lifeline

While the network extension reports the host contained, the agent SHALL connect to the endpoint it reaches the server through by the lifeline addresses the extension reports its filter enforces, or by the addresses it sent where the extension does not report them, trying each in turn with an equal share of the time left to connect, for its uploads and command polls, its token refresh and re-enrollment, and the control channel, because the system resolver answers nothing on a contained host. Connections to other destinations, and every connection while the host is not contained, SHALL be dialed as before. A control channel to a proxied server SHALL reach the proxy at the same address the lifeline pins for it and SHALL establish its own tunnel through it, naming the server inside the tunnel request rather than resolving it, so the channel reconnects while the host is contained. The agent SHALL take the dial over only for a proxy whose protocol it speaks, and SHALL leave any other proxy dialed as before, because a proxy sent a request it cannot parse would be worse off than one that is merely unreachable while contained: the request carries the credentials the operator configured on it. The protocols the agent speaks SHALL be HTTP and HTTPS proxies, tunnelled with CONNECT, and SOCKS5 proxies, tunnelled with their own handshake. A SOCKS5 proxy SHALL be given the server as a NAME to resolve rather than an address, because a contained host cannot resolve it. An HTTPS proxy SHALL be spoken to over TLS before any bytes are written to it, so the credentials on the tunnel request do not cross the path in the clear, and that TLS SHALL use the configuration the agent applies to its own traffic through the same proxy, differing only in the name verified, which SHALL be the proxy's; a stricter configuration would fail only the control channel while the agent's uploads and polls kept working, which presents as the fault this requirement exists to remove. Credentials carried by that address SHALL be presented on the tunnel request, as they are for the agent's other traffic through the same proxy. A tunnel the proxy refuses SHALL fail the connection rather than yield one that carries nothing. A tunnel whose caller has given up SHALL fail promptly rather than wait out the network: a proxy that accepts a connection and then says nothing would otherwise hold a dial nobody is waiting for until the socket itself failed. The deadline that bounds establishing the tunnel SHALL NOT remain on the connection afterwards, because the stream that runs over it is long-lived and would be torn down when that deadline passed. Before its first connection to the server, the agent SHALL adopt the containment the network extension persisted, pinning its addresses, so an agent that must enroll on a contained host reaches the server; a state the extension reports SHALL replace it, and a persisted state that is not a containment, that the network extension would itself have refused, or that describes an endpoint other than the one the agent is configured for SHALL leave the host uncontained rather than be adopted in part.

#### Scenario: An agent starting on a contained host reaches the server

- **GIVEN** a contained host whose network extension persisted the containment and the lifeline addresses it holds
- **WHEN** the agent starts, before the extension has reported its status
- **THEN** its connections to the server go to those addresses, nothing is sent to the extension, and a persisted state that is not a containment, that names another endpoint, or that the extension would have refused leaves the host uncontained

#### Scenario: Contained dials use the lifeline

- **GIVEN** a contained host whose lifeline is two server addresses
- **WHEN** the agent connects to the server
- **THEN** it dials the first address, and the second when the first fails

#### Scenario: A released host dials the server by name

- **GIVEN** a host whose containment was released
- **WHEN** the agent connects to the server
- **THEN** it dials the server by name

#### Scenario: A proxied control channel tunnels through the proxy

- **GIVEN** a contained host whose agent reaches the server through a proxy named by host name
- **WHEN** the control channel connects
- **THEN** it dials the proxy's lifeline addresses, names the server only inside the tunnel request, and presents the credentials the proxy's configured address carries
- **AND** a proxy whose protocol the agent does not speak is dialed as it was before, rather than being sent a request it cannot parse along with its credentials
- **AND** a tunnel the proxy refuses fails the connection rather than yielding one that carries nothing
- **AND** a tunnel whose caller has given up fails promptly rather than waiting out a proxy that has gone silent
- **AND** no deadline from establishing the tunnel remains on the connection the stream then runs over

#### Scenario: A SOCKS5 proxy is spoken to in its own protocol

- **GIVEN** a contained host whose agent reaches the server through a SOCKS5 proxy named by host name
- **WHEN** the control channel connects
- **THEN** it reaches the proxy at the pinned address, completes a SOCKS5 handshake rather than sending a CONNECT, and hands the proxy the server as a name to resolve
- **AND** the credentials the proxy's configured address carries are offered in that handshake

#### Scenario: An HTTPS proxy is reached over TLS first

- **GIVEN** a contained host whose agent reaches the server through an HTTPS proxy
- **WHEN** the control channel connects
- **THEN** the first bytes it writes open a TLS handshake, not a tunnel request that would carry the operator's credentials in the clear
- **AND** the proxy's certificate is verified against the proxy's own name under the configuration the agent applies to its other traffic through that proxy
- **AND** a certificate that configuration rejects fails the connection with a message naming the proxy

### Requirement: The lifeline is kept current while contained

While the host is contained, the agent SHALL re-resolve its lifeline every five minutes and send the network extension an update at the current state's version and epoch when the addresses changed, and nothing when they did not. An update SHALL NOT be dialed through until the network extension reports that its filter enforces exactly that lifeline, because sending an update only hands it to the extension and says nothing about whether it was accepted or applied: dialing addresses the filter does not allow, while it still allows the ones it holds, would close the lifeline the refresh exists to keep open. An update the extension does not report as applied SHALL be sent again at the next refresh or extension status, so a refusal, a failed apply, and a send that never arrived are each retried rather than remembered as delivered. Where the network extension does not report the lifeline it applied, which is one older than the agent, the agent SHALL dial the addresses it sent, since no confirmation is coming and dialing nothing would leave it unable to reach the server at all. An agent that starts while the host is contained SHALL learn the containment from the extension's status and send the lifeline it resolves once. After its connection to the extension is re-established, the agent SHALL send the lifeline again on the next status, since a send over the dropped connection reports no delivery. Refreshes SHALL run one at a time, and SHALL NOT run on the goroutine that delivers the extension's events: a refresh resolves and sends, and doing that where events arrive stops every event behind it and drops them once the receiver's buffer fills. A status SHALL be recorded as it arrives and the refresh it calls for requested, with requests that arrive together answered by one refresh. The extension's `ne_containment_status` control events SHALL be consumed by the agent and never uploaded as telemetry.

#### Scenario: A moved server address reaches the extension

- **GIVEN** a contained host
- **WHEN** the server's name resolves to different addresses at the next refresh
- **THEN** the agent sends the extension the new addresses at the same version and epoch

#### Scenario: Dials follow the lifeline the extension confirms

- **GIVEN** a contained host whose server has moved, so a refresh sends addresses the extension has not confirmed
- **WHEN** the agent connects to the server before that confirmation arrives
- **THEN** it dials the lifeline the extension reports its filter enforces, not the one just sent
- **AND** once a status reports the new lifeline as applied, it dials that

#### Scenario: A status does not wait for the lifeline lookup

- **GIVEN** a contained host whose lifeline lookup is slow
- **WHEN** the extension reports a status that calls for a refresh
- **THEN** recording the status returns without waiting for the lookup

#### Scenario: A lifeline no status confirms is sent again

- **GIVEN** a contained host whose lifeline was sent and which no extension status has confirmed
- **WHEN** the next refresh runs and resolves the same addresses
- **THEN** the lifeline is sent again rather than treated as delivered because it was sent once

#### Scenario: A refresh the extension did not apply is sent again

- **GIVEN** a contained host whose extension keeps reporting a lifeline other than the one the agent sent, because it refused the update or its filter apply failed
- **WHEN** each status arrives
- **THEN** the agent sends the lifeline again rather than treating it as delivered

#### Scenario: An undelivered lifeline refresh is sent again

- **GIVEN** a contained host whose lifeline refresh could not be delivered to the network extension
- **WHEN** the extension next reports its status
- **THEN** the agent sends the lifeline again, and dials the server through those addresses only once it was delivered

#### Scenario: A reconnected extension is sent the lifeline again

- **GIVEN** a contained host whose agent sent the extension its lifeline
- **WHEN** the connection to the extension drops, is re-established, and the extension reports its status
- **THEN** the agent sends the lifeline again, and its dials stay pinned meanwhile

#### Scenario: A restarted agent refreshes the lifeline

- **GIVEN** an agent that starts on a host the network extension holds contained
- **WHEN** the extension reports that status
- **THEN** the agent sends the lifeline it resolves once, and not again for the same status

#### Scenario: Containment status is not uploaded

- **GIVEN** the network extension reports its containment status
- **WHEN** the agent receives it beside telemetry
- **THEN** the status is consumed and only the telemetry is queued for upload

### Requirement: Set-watched-paths command

The system SHALL execute a `set_watched_paths` command by forwarding the watched-path set to the local Endpoint Security extension, and SHALL report the set's `version` and the number of entries forwarded.

The payload SHALL carry `{version, paths}` and MAY carry `epoch`, where each `paths` entry carries `{path, match}`. The executor SHALL validate, before forwarding, that `version` is a positive integer and that `paths` is a JSON array, and SHALL NOT validate the entries or `epoch`: they are addressed to the extension, which skips an entry it does not understand, and the agent forwards the raw payload bytes so the wire shape stays identical across server, agent, and extension. An empty `paths` array SHALL be forwarded, since it is how the server removes every path it added.

#### Scenario: Watched paths forwarded successfully

- **GIVEN** a `set_watched_paths` command with a positive `version`, a `paths` array, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the extension receives exactly the payload bytes the server sent
- **AND** the executor reports completed with the version and the count of entries in the payload

#### Scenario: A watched-path payload is invalid

- **GIVEN** a `set_watched_paths` command whose payload is not JSON, whose `version` is absent, zero, or negative, or whose `paths` is absent or not a JSON array
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid field
- **AND** the extension bridge is not invoked

#### Scenario: The watched-path set cannot reach the extension

- **GIVEN** a valid `set_watched_paths` payload
- **WHEN** the agent has no extension bridge, or the transport to the extension returns an error
- **THEN** the executor reports failed with a reason that says which of the two happened
