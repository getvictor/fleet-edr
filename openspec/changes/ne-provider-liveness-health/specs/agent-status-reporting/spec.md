# Agent status reporting: network extension capture-provider liveness delta

## ADDED Requirements

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
