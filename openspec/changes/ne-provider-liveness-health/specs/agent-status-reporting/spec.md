# agent-status-reporting Specification

## ADDED Requirements

### Requirement: Network extension health reflects capture-provider liveness

The network extension's XPC listener starts before its capture providers do, so an established XPC session is evidence that the extension PROCESS is running and is not evidence that anything is capturing. Health for that component therefore MUST NOT be derived from XPC connectivity alone.

The network extension SHALL report which of its capture providers are running, and SHALL re-report that state whenever an agent completes the XPC handshake, because the state is level-triggered: an agent that connects after the providers started would otherwise wait for a transition that never comes.

The agent SHALL grade the `network_extension` component from that report. A report naming no running provider SHALL be graded unhealthy even while the XPC session is established, because the extension is running and nothing is capturing. A provider the extension reports as stopped SHALL be graded unhealthy and named in the component message. While the XPC session is established but no report has yet arrived, the component SHALL be graded degraded rather than healthy, so connectivity is never taken as proof of capture.

A capture provider that is deliberately disabled SHALL be reported as absent rather than stopped, and absence SHALL NOT by itself make the component unhealthy. DNS proxying is opt-in, so a host that has deliberately disabled it is correctly configured, not degraded. The extension SHALL distinguish a deliberate stop from a fault by the reason the platform gives for the stop.

#### Scenario: An extension with no running capture provider is unhealthy

- **GIVEN** the network extension process is running and its XPC session is established
- **WHEN** the extension reports that no capture provider is running
- **THEN** the `network_extension` component reports status `unhealthy` with reason `no_providers_running`

#### Scenario: A stopped capture provider is unhealthy and named

- **GIVEN** the network extension has reported a capture provider running
- **WHEN** that provider stops for a reason that is not a deliberate disable
- **THEN** the `network_extension` component reports status `unhealthy` with reason `provider_stopped`
- **AND** the component message names the provider that stopped

#### Scenario: A deliberately disabled provider does not make the component unhealthy

- **GIVEN** an operator has disabled the opt-in DNS proxy
- **WHEN** the extension reports its remaining running providers
- **THEN** the disabled provider is absent from the report rather than reported as stopped
- **AND** the `network_extension` component reports status `healthy`

#### Scenario: Connectivity without a provider report is degraded, not healthy

- **GIVEN** the network extension XPC session has just been established
- **WHEN** no provider report has arrived yet
- **THEN** the `network_extension` component reports status `degraded` with reason `awaiting_provider_status`
