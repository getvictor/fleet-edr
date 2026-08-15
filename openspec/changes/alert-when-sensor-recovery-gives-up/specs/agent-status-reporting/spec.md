# Agent status reporting: durable record of an exhausted repair delta

## ADDED Requirements

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
