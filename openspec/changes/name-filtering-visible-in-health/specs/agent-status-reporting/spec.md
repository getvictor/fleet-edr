## MODIFIED Requirements

### Requirement: Network extension health reflects capture-provider liveness

The network extension's XPC listener starts before its capture providers do, so an established XPC session is evidence that the extension PROCESS is running and is not evidence that anything is capturing. Health for that component therefore MUST NOT be derived from XPC connectivity alone.

The network extension SHALL report which of its capture providers are running, and SHALL re-report that state whenever an agent completes the XPC handshake, because the state is level-triggered: an agent that connects after the providers started would otherwise wait for a transition that never comes.

The agent SHALL grade the `network_extension` component from that report. A report naming at least one running provider and no stopped provider SHALL be graded healthy. A report naming no running provider SHALL be graded unhealthy even while the XPC session is established, because the extension is running and nothing is capturing. A provider the extension reports as stopped SHALL be graded unhealthy and named in the component message. While the XPC session is established but no report has yet arrived, the component SHALL be graded degraded rather than healthy, so connectivity is never taken as proof of capture.

The extension SHALL distinguish three outcomes of a stop, using the reason the platform gives, and none of them SHALL by itself make the component unhealthy except the fault. A stop that means the hosting session is going away or being replaced SHALL drop the provider from the report, for any provider, because it occurs on ordinary logout and on activation and its last state describes nothing that still exists. A stop that means an operator switched the provider off SHALL be reported as `disabled` for the optional DNS proxy, which is opt-in and therefore correctly configured when off; switching off the mandatory content filter SHALL be reported as stopped, so a host left without network capture stays visible. Every other reason SHALL be reported as stopped.

A provider reported `disabled` SHALL stay reported across extension restarts. A provider that is switched off never starts and therefore never stops, so a fresh extension process observes no transition that would tell it: the extension SHALL therefore remember which providers were switched off and report them from its first message, and SHALL correct that memory when such a provider is next seen capturing. It SHALL NOT read the state from the system's own configuration: measured on a live host, that answers `false` inside the extension in the same process and second as its own log line saying the provider started, so reading it would report every host as switched off. A provider disabled before the extension first recorded one SHALL be reported as absent, as it was, since nothing observed it stopping.

A `disabled` provider SHALL be reported rather than omitted, and SHALL be graded as a state and not a fault: its own component SHALL say it is turned off, carrying a reason that distinguishes it from a provider that is capturing and from one that stopped, and it SHALL NOT make its parent component unhealthy. Omitting it, which an earlier version did, is indistinguishable from an extension too old to report anything, and leaves a reader unable to tell a host that switched the provider off from one that never said. That reader exists: host containment's restriction on which names a contained host resolves is the DNS proxy's work, and a contained host whose proxy is off resolves any name its own resolvers answer.

#### Scenario: A disabled provider survives a restart

- **GIVEN** an operator has switched off the optional DNS proxy
- **WHEN** the extension restarts, so the provider never starts and never stops
- **THEN** its first report still names the provider `disabled`
- **AND** a provider found capturing again is no longer reported that way

#### Scenario: A disabled provider is reported, not omitted

- **GIVEN** an operator switches off the optional DNS proxy
- **WHEN** the extension reports provider liveness
- **THEN** the provider is reported `disabled` rather than omitted, its own component says it is turned off with a reason of its own, and neither it nor its parent component is graded a fault

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
- **THEN** the disabled provider is reported `disabled` rather than stopped, and stays in the report
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

### Requirement: Remediation never overrides a deliberate operator decision

A capture provider the operator has deliberately disabled SHALL NOT be re-enabled by remediation. DNS proxying is opt-in, so re-enabling it against an operator's decision would make the product fight its own administrator, and an automatic control that cannot be turned off is worse than the outage it prevents.

The agent SHALL distinguish the two cases by the report it already receives: a deliberately disabled provider is reported `disabled`, and only a provider reported stopped is eligible for remediation. Neither a `disabled` provider nor one missing from the map is eligible, so an extension that reports the state and one that predates it are both safe from remediation.

#### Scenario: A deliberately disabled provider is not re-enabled

- **GIVEN** an operator has disabled the opt-in DNS proxy
- **AND** the network extension therefore reports it `disabled` rather than stopped
- **WHEN** the agent evaluates the report for remediation
- **THEN** no remediation is attempted for that provider
- **AND** the provider stays disabled

### Requirement: Transition records distinguish a fault from a supported configuration

A record that fires on ordinary operation is one operators learn to ignore, which destroys the value of the records that matter. Transition recording SHALL therefore be limited to state the agent has actually observed changing, and SHALL NOT treat a supported configuration as a fault.

The first report received after an agent connects SHALL establish a baseline without recording transitions, because the extension re-publishes provider liveness on every handshake and that report describes state the agent has not observed change.

A provider reported `disabled`, or missing from the report entirely, SHALL NOT produce a transition record. An operator who has deliberately disabled an optional provider is running a supported configuration, and both are how an extension reports one. Neither SHALL leave the provider's last observed state standing as the baseline: turning the provider back on is a transition, and a baseline still holding the state from before the opt-out would read it as no change and record nothing.

The record SHALL carry the platform's own reason for a stop, unreduced, so that a consumer can distinguish an operator-driven stop from one produced by an upgrade or a session ending without depending on a verdict already formed on its behalf.

#### Scenario: Reconnecting does not manufacture transitions

- **GIVEN** an agent has just connected to the extension
- **WHEN** it receives the extension's first liveness report
- **THEN** no transition is recorded, whatever that report contains

#### Scenario: A deliberately disabled provider is not recorded as a fault

- **GIVEN** an operator has disabled an optional capture provider
- **AND** the extension therefore reports it `disabled`, or stops reporting it at all
- **WHEN** the agent receives that report
- **THEN** no transition is recorded for that provider

#### Scenario: A stop record carries the platform stop reason

- **GIVEN** a capture provider stops and the extension reports the platform's reason
- **WHEN** the agent records the transition
- **THEN** the record carries that reason unreduced

### Requirement: The agent reports each capture provider as its own component

The agent SHALL report the state of each capture provider the extension reports to it as its own component in the status snapshot, in addition to the existing single component for the extension that owns them.

The collapsed component cannot carry this. It reports the worst state among the providers, so a host whose providers are all capturing and a host with one wedged provider are indistinguishable to any reader of the snapshot. The server needs each provider's state as a POSITIVE claim, because the only way to detect a provider that has stopped delivering while believing itself healthy is to contradict its own claim against the telemetry that actually arrived.

A provider the extension does NOT report SHALL NOT appear in the snapshot, and one that stops being reported SHALL be removed from it, because a retained component would publish a positive claim for a provider that is no longer reporting one.

A provider the extension reports as switched off by an operator SHALL appear as its own component saying so, under a reason that distinguishes it from a provider that is capturing and from one that stopped, and SHALL NOT be graded a fault or make its owning component one. It SHALL NOT be a claim to be capturing: a consumer that contradicts such claims against arriving telemetry would otherwise report a fault on a provider that is simply not running by choice, which is the same outcome omitting it used to buy. Reporting it rather than omitting it is what lets a reader tell a provider an operator switched off from one an extension never mentioned, which omission cannot express (issue #1078).

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

- **GIVEN** a snapshot carrying a component for a provider
- **WHEN** the extension stops reporting that provider at all
- **THEN** the next snapshot does not carry a component for it
- **AND** the extension's own component is not degraded by its absence

#### Scenario: A disabled provider is its own component

- **GIVEN** an extension reporting a provider an operator switched off
- **WHEN** the agent posts its status snapshot
- **THEN** the snapshot carries a component for that provider saying it is turned off, under its own reason
- **AND** neither it nor the extension that owns it is graded a fault

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
