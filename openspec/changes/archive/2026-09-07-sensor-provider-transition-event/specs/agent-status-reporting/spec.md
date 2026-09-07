# Agent status reporting: durable capture-provider transition events delta

## ADDED Requirements

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
