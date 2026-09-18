## MODIFIED Requirements

### Requirement: Network extension health reflects capture-provider liveness

The network extension's XPC listener starts before its capture providers do, so an established XPC session is evidence that the extension PROCESS is running and is not evidence that anything is capturing. Health for that component therefore MUST NOT be derived from XPC connectivity alone.

The network extension SHALL report which of its capture providers are running, and SHALL re-report that state whenever an agent completes the XPC handshake, because the state is level-triggered: an agent that connects after the providers started would otherwise wait for a transition that never comes.

The agent SHALL grade the `network_extension` component from that report. A report naming at least one running provider and no stopped provider SHALL be graded healthy. A report naming no running provider SHALL be graded unhealthy even while the XPC session is established, because the extension is running and nothing is capturing. A provider the extension reports as stopped SHALL be graded unhealthy and named in the component message. While the XPC session is established but no report has yet arrived, the component SHALL be graded degraded rather than healthy, so connectivity is never taken as proof of capture.

The extension SHALL distinguish three outcomes of a stop, using the reason the platform gives, and none of them SHALL by itself make the component unhealthy except the fault. A stop that means the hosting session is going away or being replaced SHALL drop the provider from the report, for any provider, because it occurs on ordinary logout and on activation and its last state describes nothing that still exists. A stop that means an operator switched the provider off SHALL be reported as `disabled` for the optional DNS proxy, which is opt-in and therefore correctly configured when off; switching off the mandatory content filter SHALL be reported as stopped, so a host left without network capture stays visible. Every other reason SHALL be reported as stopped.

A `disabled` provider SHALL be reported rather than omitted, and SHALL be graded as a state and not a fault: its own component SHALL say it is turned off, carrying a reason that distinguishes it from a provider that is capturing and from one that stopped, and it SHALL NOT make its parent component unhealthy. Omitting it, which an earlier version did, is indistinguishable from an extension too old to report anything, and leaves a reader unable to tell a host that switched the provider off from one that never said. That reader exists: host containment's restriction on which names a contained host resolves is the DNS proxy's work, and a contained host whose proxy is off resolves any name its own resolvers answer.

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
