## MODIFIED Requirements

### Requirement: Remediation never overrides a deliberate operator decision

A capture provider the operator has deliberately disabled SHALL NOT be re-enabled by remediation. DNS proxying is opt-in, so re-enabling it against an operator's decision would make the product fight its own administrator, and an automatic control that cannot be turned off is worse than the outage it prevents.

The agent SHALL distinguish the two cases by the report it already receives: a deliberately disabled provider is reported `disabled`, and only a provider reported stopped is eligible for remediation. Neither a `disabled` provider nor one missing from the map is eligible, so an extension that reports the state and one that predates it are both safe from remediation.

Eligibility alone does not settle it, because an operator can disable a provider while a repair for it is already running. On learning that a provider is `disabled`, the agent SHALL stop any enable it currently has in flight for that provider and SHALL record nothing of that attempt. The agent cannot undo an enable that already completed before the decision reached it, so this bounds how long it keeps working against the operator rather than removing the race; what it does guarantee is that the agent stops as soon as it is told, and does not resume.

Only the affirmative `disabled` state SHALL do this. Absence SHALL NOT, because absence is also how a host reports a provider before anything has started, how an extension predating the state reports a disable, and what remains when a report cannot be decoded; abandoning a repair on any of those would be the opposite failure.

A provider whose repair was abandoned this way SHALL keep no state from that episode, so that a provider later turned back on which stops again is treated as a new fault, with a full grace window and a full attempt budget, rather than meeting the remains of the episode the operator interrupted.

#### Scenario: A deliberately disabled provider is not re-enabled

- **GIVEN** an operator has disabled the opt-in DNS proxy
- **AND** the network extension therefore reports it `disabled` rather than stopped
- **WHEN** the agent evaluates the report for remediation
- **THEN** no remediation is attempted for that provider
- **AND** the provider stays disabled

#### Scenario: An enable already running is abandoned

- **GIVEN** the agent has an enable in flight for a stopped provider
- **WHEN** a report arrives saying that provider is now `disabled`
- **THEN** the agent stops the enable in flight
- **AND** records no attempt and no escalation for it
- **AND** a report that merely omits the provider does neither of those, because absence is not a decision

#### Scenario: A provider turned back on starts fresh

- **GIVEN** a provider whose repair was abandoned because an operator disabled it
- **WHEN** it is later turned back on and stops again
- **THEN** the agent serves a full grace window before remediating it
- **AND** counts the next remediation as the first attempt of a full budget

### Requirement: Remediation attempts are bounded and escalate on exhaustion

Repeated failure to restore a provider means the fault is not one that re-enabling fixes, so the agent SHALL bound how many times it retries and SHALL space successive attempts. An unbounded repair loop would rewrite system configuration indefinitely and would hide the underlying fault behind apparently ongoing recovery.

When the attempt budget is exhausted the component SHALL report a reason distinct from the one it reports while remediation is still being attempted, so that an operator can tell "recovery is in progress" from "recovery failed and a human is required".

A successful remediation SHALL reset the budget, so a host that fails intermittently over a long period is retried each time rather than being permanently written off.

An enable that finishes after the stop it was started for has ended SHALL have its outcome discarded. A provider can be reported running, or disabled, while an enable is still running, and can stop again before that enable returns; attributing the finished attempt to the stop that now stands would spend a budget that stop never used, and on the last attempt of a budget would tell the operator recovery had been given up on a fault nothing had yet been tried for.

#### Scenario: Repeated failures stop retrying and escalate

- **GIVEN** a capture provider is reported stopped
- **WHEN** every remediation attempt in the budget fails to restore it
- **THEN** the agent stops attempting further remediation for that stop
- **AND** the `network_extension` component reports that automatic recovery failed

#### Scenario: A successful remediation restores the budget

- **GIVEN** a provider was restored by remediation after earlier attempts failed
- **WHEN** the same provider is later reported stopped again
- **THEN** the agent attempts remediation again with a full budget

#### Scenario: An attempt that outlives its episode is discarded

- **GIVEN** an enable is in flight for a stopped provider
- **AND** that provider is reported running and then stops again before the enable returns
- **WHEN** the enable finishes
- **THEN** nothing of it is recorded against the stop that now stands
- **AND** no escalation is published for that stop, even when the finished attempt was the last of its own budget
