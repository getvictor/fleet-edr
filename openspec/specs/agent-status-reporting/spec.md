# agent-status-reporting Specification

## Purpose

The agent maintains a per-component health registry (extension XPC connectivity, queue, uploader) and reports it to the server on check-in, distinguishing never-connected from connection-lost so an operator can tell a fresh install from a dropped session.

## Requirements

### Requirement: The agent maintains a per-component health registry

The agent SHALL maintain a health registry mapping each monitored component to a current condition carrying a status, a machine-readable reason, a human-readable message, and the timestamp the condition last changed. The registry SHALL be updated from the agent's existing per-service XPC connectivity state and its connect and disconnect transitions. The last-transition timestamp of a component SHALL advance only when that component's status actually changes, so that the timestamp denotes the start of the current condition.

#### Scenario: A connected extension is healthy

- **GIVEN** the endpoint-security extension XPC session is established
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `healthy` with reason `activated`

#### Scenario: The last-transition timestamp is stable across unchanged reads

- **GIVEN** a component whose status has not changed since it was last set
- **WHEN** the registry is updated again with the same status
- **THEN** the component's last-transition timestamp is unchanged

### Requirement: The agent distinguishes never-connected from connection-lost per extension

For each monitored extension the agent SHALL report reason `never_connected` while it has never established a session since the agent started, and reason `connection_lost` once it has established a session and then lost it while the agent continued running. Both conditions SHALL carry status `unhealthy`.

#### Scenario: A fresh install with an unactivated extension reports never-connected

- **GIVEN** an agent that has started and never established the endpoint-security XPC session
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `unhealthy` with reason `never_connected`

#### Scenario: A dropped session reports connection-lost

- **GIVEN** an extension whose XPC session was established and then dropped while the agent kept running
- **WHEN** the registry is read
- **THEN** that component reports status `unhealthy` with reason `connection_lost`

### Requirement: The agent posts an idempotent status snapshot

The agent SHALL post its current health as a complete snapshot to the host check-in endpoint, authenticated with its host token, carrying the agent version and the full list of component conditions on every post. The snapshot SHALL be idempotent: re-posting the same state SHALL leave the server's view unchanged, and each post SHALL fully replace the prior snapshot for that host rather than appending to a log.

#### Scenario: A post carries the full component list

- **GIVEN** a registry holding the endpoint-security and network-extension components
- **WHEN** the agent posts a status snapshot
- **THEN** the request carries the agent version and both components with their status, reason, message, and last-transition timestamp

#### Scenario: Re-posting an unchanged snapshot is a no-op for the server view

- **GIVEN** a snapshot the agent has already posted successfully
- **WHEN** the agent posts the identical snapshot again
- **THEN** the server's stored health for that host is unchanged

### Requirement: The agent reports on startup, on transition, and periodically

The agent SHALL post a status snapshot shortly after startup, again whenever a component's status changes, and on a periodic floor while running. Transition-triggered posts SHALL be debounced so a burst of connect retries collapses into a single post.

#### Scenario: A startup post makes a dead sensor visible immediately

- **GIVEN** an agent starting with an extension that never connects
- **WHEN** the agent has started
- **THEN** it posts a snapshot showing that extension `unhealthy` without waiting for the periodic floor

#### Scenario: A status change triggers a post

- **GIVEN** a running agent that has already posted a snapshot
- **WHEN** an extension transitions from connected to lost
- **THEN** the agent posts an updated snapshot reflecting the transition

#### Scenario: A burst of retries collapses into one post

- **GIVEN** an extension failing to connect and retrying rapidly with no change in resulting status
- **WHEN** several retries occur within the debounce window
- **THEN** the agent posts at most one snapshot for that burst

### Requirement: Status report carries host inventory

The agent SHALL include a host inventory block in every status report: the kernel hostname, the OS product name, the OS product version, and the OS build identifier (the agent's own version rides the report's existing top-level field, not the inventory block). Inventory SHALL be collected without spawning external processes and SHALL be re-collected for each post, and a field whose source is unavailable SHALL be reported empty rather than failing the report. Because the report is posted on startup, on component transitions, and on the periodic floor, a hostname rename, OS upgrade, or agent upgrade MUST be reflected in a posted report no later than one periodic interval after it takes effect on the host, without requiring an agent restart.

#### Scenario: Inventory is included in the status post

- **GIVEN** a running agent on a macOS host
- **WHEN** the agent posts a status report
- **THEN** the payload carries the hostname, OS product name, OS product version, and OS build alongside the component snapshot

#### Scenario: Missing OS metadata degrades to empty fields

- **GIVEN** an agent on a system where the OS version source is unreadable
- **WHEN** the agent posts a status report
- **THEN** the report is still posted with the unavailable OS fields empty
- **AND** the component snapshot is unaffected

### Requirement: Enrollment reports friendly OS identity

The agent's enrollment request SHALL carry the same friendly OS product version it reports in inventory, rather than a Go runtime platform token such as `darwin`.

#### Scenario: Fresh enrollment carries the OS product version

- **GIVEN** an agent enrolling on macOS
- **WHEN** it sends the enrollment request
- **THEN** the OS version field carries the OS product version (for example `26.4`), not the literal platform token `darwin`

### Requirement: An exhausted repair is recorded durably, once

When the agent's automatic repair of a stopped capture provider exhausts its attempt budget, the agent SHALL record that outcome as a durable event in addition to publishing it to its health state. Health reports only what is true now, so once an operator restores the provider by hand the health view reads healthy again and nothing records that the host went uncaptured in the meantime. The durable record is what an analyst reads afterwards, the same argument that justifies recording the stop itself.

The record SHALL identify the provider, how many repair attempts were made, and which failure shape was reached: the repair command failing, or the repair reporting success while the provider stayed stopped.

The record SHALL be emitted exactly ONCE per stop episode, at the point the budget is spent. It MUST NOT be emitted from the path that re-publishes the escalation to health, which runs again on every subsequent liveness report: health is level state and idempotent under repetition, whereas a durable record is appended, so emitting there would produce one record per report for as long as the provider stayed stopped. The extension re-publishes liveness on every agent handshake, so that is a flood rather than a duplicate.

A provider that is restored within the attempt budget SHALL produce no such record. A repair that works is not something an operator needs to be told about, and reporting one would raise an alert on every host that healed itself.

A failure to record SHALL NOT interrupt the agent or the health escalation, which is already published by that point.

#### Scenario: An exhausted repair is recorded

- **GIVEN** a capture provider the agent has been unable to restore
- **WHEN** the agent uses the last attempt in its budget
- **THEN** the agent records a durable event naming the provider, the number of attempts, and the failure shape

#### Scenario: The record is not repeated while the provider stays stopped

- **GIVEN** an agent that has already recorded an exhausted repair for a provider
- **WHEN** further liveness reports arrive with that provider still stopped
- **THEN** the agent re-asserts the escalation to its health state
- **AND** records no further durable events for it

#### Scenario: A successful repair records nothing

- **GIVEN** a capture provider the agent restores within its attempt budget
- **WHEN** the extension reports it running again
- **THEN** the agent records no exhausted-repair event

### Requirement: Network extension health reflects capture-provider liveness

The network extension's XPC listener starts before its capture providers do, so an established XPC session is evidence that the extension PROCESS is running and is not evidence that anything is capturing. Health for that component therefore MUST NOT be derived from XPC connectivity alone.

The network extension SHALL report which of its capture providers are running, and SHALL re-report that state whenever an agent completes the XPC handshake, because the state is level-triggered: an agent that connects after the providers started would otherwise wait for a transition that never comes.

The agent SHALL grade the `network_extension` component from that report. A report naming at least one running provider and no stopped provider SHALL be graded healthy. A report naming no running provider SHALL be graded unhealthy even while the XPC session is established, because the extension is running and nothing is capturing. A provider the extension reports as stopped SHALL be graded unhealthy and named in the component message. While the XPC session is established but no report has yet arrived, the component SHALL be graded degraded rather than healthy, so connectivity is never taken as proof of capture.

The extension SHALL distinguish a stop that means deliberate absence from a stop that means a fault, using the reason the platform gives, and SHALL report a deliberately absent provider as absent rather than stopped. Absence SHALL NOT by itself make the component unhealthy. A stop that means the hosting session is going away or being replaced SHALL be treated as absence for any provider, because it occurs on ordinary logout and on activation. A stop that means an operator switched the provider off SHALL be treated as absence only for the optional DNS proxy, which is opt-in and therefore correctly configured when off; switching off the mandatory content filter SHALL be reported as stopped, so a host left without network capture stays visible.

#### Scenario: A report with a running provider and no fault is healthy

- **GIVEN** the network extension XPC session is established
- **WHEN** the extension reports at least one capture provider running and none stopped
- **THEN** the `network_extension` component reports status `healthy`

#### Scenario: An extension with no running capture provider is unhealthy

- **GIVEN** the network extension process is running and its XPC session is established
- **WHEN** the extension reports that no capture provider is running
- **THEN** the `network_extension` component reports status `unhealthy` with reason `no_providers_running`

#### Scenario: A stopped capture provider is unhealthy and named

- **GIVEN** the network extension has reported a capture provider running
- **WHEN** that provider stops for a reason that is not a deliberate absence
- **THEN** the `network_extension` component reports status `unhealthy` with reason `provider_stopped`
- **AND** the component message names the provider that stopped

#### Scenario: A deliberately disabled provider does not make the component unhealthy

- **GIVEN** an operator has disabled the opt-in DNS proxy
- **WHEN** the extension reports its remaining running providers
- **THEN** the disabled provider is absent from the report rather than reported as stopped
- **AND** the `network_extension` component reports status `healthy`

#### Scenario: Disabling the mandatory content filter stays visible

- **GIVEN** the network extension has reported the content filter running
- **WHEN** an operator switches the content filter off
- **THEN** the content filter is reported as stopped rather than absent
- **AND** the `network_extension` component reports status `unhealthy`

#### Scenario: Connectivity without a provider report is degraded, not healthy

- **GIVEN** the network extension XPC session has just been established
- **WHEN** no provider report has arrived yet
- **THEN** the `network_extension` component reports status `degraded` with reason `awaiting_provider_status`

### Requirement: Capture-provider status is a control message, not telemetry

The provider-liveness report travels on the same XPC channel as events, because that channel only surfaces messages carrying a data blob. It is nonetheless agent-local state: the agent SHALL consume it for health and SHALL NOT place it on the upload queue or send it to the server. Recognising the message SHALL depend only on its event type, so that a report whose payload is malformed is still kept out of telemetry rather than uploaded as an unrecognised event.

#### Scenario: A provider status message is not uploaded

- **GIVEN** the agent is receiving events from the network extension
- **WHEN** a capture-provider status message arrives
- **THEN** the agent updates `network_extension` health from it
- **AND** the message is not added to the upload queue

#### Scenario: Ordinary telemetry is unaffected by the filter

- **GIVEN** the agent is receiving events from the network extension
- **WHEN** an ordinary event such as `exec` or `network_connect` arrives
- **THEN** the event is enqueued for upload unchanged

### Requirement: The agent restores stopped capture providers

A capture provider that stops takes the telemetry it produces with it, so the agent SHALL attempt to restore it rather than only reporting it. When the network extension reports a provider stopped and that provider is still stopped after a grace window, the agent SHALL re-enable it.

The grace window exists because a provider stop is routine during an activation or an upgrade cutover and usually resolves on its own within seconds. Remediating instantly would race those recoveries and produce redundant configuration writes.

Remediation SHALL be driven by the reported state rather than by any inference about what caused the stop, so that triggers nobody has enumerated are covered by the same mechanism.

The agent SHALL NOT require a logged-in user to remediate, because a host at the loginwindow is exactly as blind as one with a console session and is likelier to be unattended.

#### Scenario: A stopped provider is re-enabled

- **GIVEN** the network extension reports a capture provider stopped
- **AND** the provider is still reported stopped when the grace window expires
- **WHEN** the agent runs its remediation
- **THEN** the agent re-enables that provider through the host application
- **AND** the provider resumes capturing without operator action

#### Scenario: A provider that recovers on its own is left alone

- **GIVEN** the network extension reports a capture provider stopped
- **WHEN** the provider reports itself running again before the grace window expires
- **THEN** the agent does not attempt any remediation

#### Scenario: Remediation needs no console user

- **GIVEN** no user is logged in to the host
- **WHEN** the agent remediates a stopped capture provider
- **THEN** the remediation is attempted rather than deferred to the next login

### Requirement: Remediation never overrides a deliberate operator decision

A capture provider the operator has deliberately disabled SHALL NOT be re-enabled by remediation. DNS proxying is opt-in, so re-enabling it against an operator's decision would make the product fight its own administrator, and an automatic control that cannot be turned off is worse than the outage it prevents.

The agent SHALL distinguish the two cases by the report it already receives: a deliberately disabled provider is reported as absent from the provider map, and only a provider reported stopped is eligible for remediation.

#### Scenario: A deliberately disabled provider is not re-enabled

- **GIVEN** an operator has disabled the opt-in DNS proxy
- **AND** the network extension therefore reports it absent rather than stopped
- **WHEN** the agent evaluates the report for remediation
- **THEN** no remediation is attempted for that provider
- **AND** the provider stays disabled

### Requirement: Remediation attempts are bounded and escalate on exhaustion

Repeated failure to restore a provider means the fault is not one that re-enabling fixes, so the agent SHALL bound how many times it retries and SHALL space successive attempts. An unbounded repair loop would rewrite system configuration indefinitely and would hide the underlying fault behind apparently ongoing recovery.

When the attempt budget is exhausted the component SHALL report a reason distinct from the one it reports while remediation is still being attempted, so that an operator can tell "recovery is in progress" from "recovery failed and a human is required".

A successful remediation SHALL reset the budget, so a host that fails intermittently over a long period is retried each time rather than being permanently written off.

#### Scenario: Repeated failures stop retrying and escalate

- **GIVEN** a capture provider is reported stopped
- **WHEN** every remediation attempt in the budget fails to restore it
- **THEN** the agent stops attempting further remediation for that stop
- **AND** the `network_extension` component reports that automatic recovery failed

#### Scenario: A successful remediation restores the budget

- **GIVEN** a provider was restored by remediation after earlier attempts failed
- **WHEN** the same provider is later reported stopped again
- **THEN** the agent attempts remediation again with a full budget

### Requirement: The agent reports each capture provider as its own component

The agent SHALL report the state of each capture provider the extension reports to it as its own component in the status snapshot, in addition to the existing single component for the extension that owns them.

The collapsed component cannot carry this. It reports the worst state among the providers, so a host whose providers are all capturing and a host with one wedged provider are indistinguishable to any reader of the snapshot. The server needs each provider's state as a POSITIVE claim, because the only way to detect a provider that has stopped delivering while believing itself healthy is to contradict its own claim against the telemetry that actually arrived.

A provider the extension does NOT report SHALL NOT appear in the snapshot, and one that stops being reported SHALL be removed from it. The extension reports a deliberate operator opt-out by omitting the provider, so a retained component would publish a positive claim for a provider that is switched off. That is worse than reporting nothing: a consumer that contradicts these claims against arriving telemetry would report a fault on a provider that is simply not running by choice.

A provider whose reported state is unchanged SHALL keep the instant at which it entered that state. Liveness reports arrive on every extension handshake, so re-stamping each time would report every provider as having just changed.

A provider state the agent does not recognise SHALL be reported as unknown rather than as running or stopped, so that a newer extension's vocabulary neither manufactures a claim that can be contradicted nor condemns the host.

A liveness report the agent could not READ SHALL leave the provider view unchanged. An unreadable report is indistinguishable by value from the extension reporting that no provider is running, since both present as an empty set, so acting on it would clear every provider and the next readable report would re-add them as though each had just changed. A readable report carrying no providers is different and SHALL clear them, because that is the extension stating that nothing is capturing.

The provider components SHALL be ordered stably across reports, since the server replaces its stored snapshot last-writer-wins and an unstable order would present an unchanged report as a change.

#### Scenario: Each reported provider appears as its own component

- **GIVEN** an extension reporting one provider capturing and another stopped
- **WHEN** the agent posts its status snapshot
- **THEN** the snapshot carries a component for each provider, naming its own state
- **AND** the snapshot still carries the component for the extension that owns them

#### Scenario: A provider the extension stops reporting is dropped

- **GIVEN** a snapshot carrying a component for an optional provider
- **WHEN** the operator disables that provider and the extension stops reporting it
- **THEN** the next snapshot does not carry a component for it
- **AND** the extension's own component is not degraded by its absence

#### Scenario: An unchanged provider keeps its transition instant

- **GIVEN** a provider reported in the same state across several liveness reports
- **WHEN** the agent posts each snapshot
- **THEN** the provider's component reports the instant it entered that state, not the time of the latest report

#### Scenario: A report the agent could not read leaves the provider view untouched

- **GIVEN** a snapshot carrying components for two running providers
- **WHEN** the agent receives a liveness report whose payload it cannot read
- **THEN** the provider components are unchanged, including the instants they carry
- **AND** a readable report carrying no providers does clear them

#### Scenario: An unrecognised provider state is reported as unknown

- **GIVEN** an extension reporting a provider state this agent does not recognise
- **WHEN** the agent posts its status snapshot
- **THEN** the provider's component reports unknown
- **AND** the component still identifies the provider

### Requirement: Capture-provider transitions are recorded as durable events

Component health is level state and is therefore not evidence: once a stopped provider is restored, health reports the component healthy again and no record remains that it ever stopped. Disabling security tooling is a recognised technique, so the agent SHALL record each capture-provider state change as an event that outlives the condition it describes.

The agent SHALL emit an event when a provider it has been observing changes state, carrying the provider identifier and the state it moved into.

Whether a stop was repaired SHALL be carried by the subsequent running transition rather than by an outcome recorded on the stop. Whether recovery will succeed is not known when a stop is observed, and recovery may not be attempted at all, so an outcome field would either be wrong or force the record to wait on an answer that may never arrive.

#### Scenario: A provider stopping is recorded

- **GIVEN** the agent has observed a capture provider running
- **WHEN** the extension reports that provider stopped
- **THEN** the agent records an event naming the provider and the stopped state

#### Scenario: A repaired stop is two records, not one annotated record

- **GIVEN** a capture provider has been recorded as stopped
- **WHEN** the provider is later reported running again
- **THEN** the agent records a second event naming the provider and the running state
- **AND** the two events together show both that the provider stopped and that it recovered

#### Scenario: An unchanged report is recorded once

- **GIVEN** a capture provider has been recorded as stopped
- **WHEN** the extension repeats the same state in later reports
- **THEN** no further event is recorded for that provider

### Requirement: Transition records distinguish a fault from a supported configuration

A record that fires on ordinary operation is one operators learn to ignore, which destroys the value of the records that matter. Transition recording SHALL therefore be limited to state the agent has actually observed changing, and SHALL NOT treat a supported configuration as a fault.

The first report received after an agent connects SHALL establish a baseline without recording transitions, because the extension re-publishes provider liveness on every handshake and that report describes state the agent has not observed change.

A provider reported absent SHALL NOT produce a transition record. An operator who has deliberately disabled an optional provider is running a supported configuration, and absence is how the extension reports that.

The record SHALL carry the platform's own reason for a stop, unreduced, so that a consumer can distinguish an operator-driven stop from one produced by an upgrade or a session ending without depending on a verdict already formed on its behalf.

#### Scenario: Reconnecting does not manufacture transitions

- **GIVEN** an agent has just connected to the extension
- **WHEN** it receives the extension's first liveness report
- **THEN** no transition is recorded, whatever that report contains

#### Scenario: A deliberately disabled provider is not recorded as a fault

- **GIVEN** an operator has disabled an optional capture provider
- **AND** the extension therefore reports it absent rather than stopped
- **WHEN** the agent receives that report
- **THEN** no transition is recorded for that provider

#### Scenario: A stop record carries the platform stop reason

- **GIVEN** a capture provider stops and the extension reports the platform's reason
- **WHEN** the agent records the transition
- **THEN** the record carries that reason unreduced

### Requirement: A transition record is not lost to a transient failure

The record is the only durable evidence that a provider was switched off, so the agent SHALL NOT treat a transition as observed until it has actually been recorded. A transition whose recording fails SHALL be retried on a later report rather than dropped.

A record SHALL NOT be emitted before the agent has an identity to attribute it to, because an event that cannot be attributed to a host is not evidence.

#### Scenario: A failed record is retried

- **GIVEN** a capture provider transition occurs
- **AND** recording it fails
- **WHEN** a later report repeats the same state
- **THEN** the agent attempts to record that transition again

#### Scenario: Nothing is recorded before enrollment completes

- **GIVEN** the agent has not yet completed enrollment
- **WHEN** a capture provider transition occurs
- **THEN** no event is recorded
