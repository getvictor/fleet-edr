# agent-control-channel

## ADDED Requirements

### Requirement: A queued command can be withdrawn, and ages out rather than being delivered late

The system SHALL provide an operator path to withdraw a command that no agent has picked up, and SHALL record it in a state distinct from a command an agent attempted and could not complete. An operator auditing a host has to be able to tell "nothing ran" from "something ran and went wrong", and collapsing the two into one state destroys that distinction permanently.

The system SHALL age out a command that has waited for delivery beyond a bounded window, rather than delivering it once the host becomes reachable again. This is a safety property rather than tidiness: a process-termination command addresses a process by PID, PIDs are reused, and a command delivered long after it was issued can terminate an unrelated process on that host.

Withdrawal is a request that wins only if no agent had already taken the command, and MUST NOT be treated as a guarantee that it never runs. Delivery and withdrawal race: a command is pushed while its record still says pending, and the agent begins the side effect and acknowledges asynchronously, so a withdrawal can land before that acknowledgement is recorded. When an acknowledgement arrives for a command already recorded as withdrawn or aged out, the system SHALL accept it and let the record follow what actually happened on the host. Leaving those states closed would record that nothing ran for a command that did run, which is the misreport this requirement exists to prevent.

Withdrawal and ageing out SHALL both be reachable only from the pending state. Once an agent has acknowledged a command it owns it and may already have applied the side effect, so recording either outcome would misreport what happened on the host.

Withdrawing a command SHALL require the same authority as issuing that kind of command, and MUST NOT be permitted on read access alone. Preventing a response action is itself a response decision, and an actor who could withdraw commands on a host they can only observe could disable incident response there.

#### Scenario: An operator withdraws a command no agent has taken

- **GIVEN** a command queued for a host that has not acknowledged it
- **WHEN** an operator with authority to issue that kind of command withdraws it
- **THEN** the command is recorded in a state that says no agent ran it, distinct from having been attempted and failed
- **AND** it is no longer offered to that host for delivery

#### Scenario: Withdrawal is refused once the agent has the command

- **GIVEN** a command a host has already acknowledged
- **WHEN** an operator attempts to withdraw it
- **THEN** the request is refused and the command's recorded state is unchanged, because the side effect may already have been applied

#### Scenario: A command that waited too long is aged out instead of delivered

- **GIVEN** a command that has been queued for longer than the delivery window, for a host that then asks for its pending work
- **WHEN** the system answers that request
- **THEN** the aged-out command is not among the commands delivered
- **AND** it is recorded as having expired, so an operator can see why it never ran

#### Scenario: Ageing out does not disturb a command the agent already owns

- **GIVEN** a command a host acknowledged before the delivery window elapsed
- **WHEN** the delivery window passes
- **THEN** the command's recorded state is unchanged, because the agent may have applied it

#### Scenario: A late acknowledgement corrects a withdrawn command

- **GIVEN** a command an operator withdrew after it had already been delivered to the host
- **WHEN** the agent's acknowledgement and outcome arrive afterwards
- **THEN** they are accepted and the record reports what ran on the host, rather than continuing to report that nothing did
