# Agent status reporting: automatic recovery of stopped capture providers delta

## ADDED Requirements

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
