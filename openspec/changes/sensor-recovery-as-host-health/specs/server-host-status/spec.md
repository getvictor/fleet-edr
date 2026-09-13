## ADDED Requirements

### Requirement: The server records host health episodes

A component's health is level state: it reports what is true now and is overwritten as soon as that changes. That is the right shape for a console badge and the wrong shape for accountability, because a host that stopped capturing and was later fixed by hand reads healthy afterwards and leaves no record that it was ever blind, or for how long. The system SHALL persist a health EPISODE for a component fault that requires a person to act, independently of the level state that reports it.

An episode SHALL identify the host and the component it concerns, SHALL name the kind of fault, and SHALL record when it began. It SHALL carry the fault's own machine-readable detail, so an operator reading the record does not have to parse prose to learn which component to act on.

Where a component owns several independently failing parts, the episode SHALL also name WHICH part is at fault. Two parts failing under one component are two outages and SHALL be recorded as two episodes, each keeping its own detail.

A report that cannot name the component SHALL still be recorded, because it names a host that is not capturing and that is what an operator has to act on. Such an episode has nothing to close it and stays open: reporting a fault we cannot tie to a component is honest, and inventing a component to make it resolvable would not be.

An episode's opening and closing instants SHALL both be observed on the host rather than taken from the server's clock. The interval between them is what the record exists to provide, so measuring one end by when the server processed a report would count queue backlog and delivery delay as part of the outage. An episode SHALL NOT close before it opened, whatever the reporting host's clock does between the two reports.

An episode SHALL be closed when the component it concerns reports healthy again, recording the instant it closed. An episode that has not closed SHALL be distinguishable from one that has, so "this host is not capturing now" and "this host was not capturing for eleven hours last week" are separate answers drawn from the same record.

An episode SHALL be identified by the occurrence it records, so that recording the same occurrence again changes nothing. A fault is reported once per outage, and the repetition the system actually sees is REDELIVERY of that one report: delivery is at-least-once, so a report can be processed, acknowledged poorly, and processed again. Recording SHALL therefore collapse on the occurrence whether or not the episode has closed in between, and a later outage SHALL open its own episode because it is its own occurrence.

Identifying an episode by "a fault of this kind is open for this component" instead is NOT sufficient, and is worth stating because it is the obvious design and it is wrong here: the key stops matching the moment the episode closes, so a redelivery arriving after a recovery records the same outage a second time.

A component reporting healthy when no episode is open SHALL be accepted and change nothing. A host reporting healthy for a component it has never reported a fault for is the overwhelmingly common case and is not an error.

#### Scenario: A fault that needs a person opens an episode

- **GIVEN** a host whose capture provider stopped and whose agent reports that its repair attempts are exhausted
- **WHEN** the server records the failure
- **THEN** an open episode exists for that host and component, naming the fault kind and the instant it began
- **AND** the instant it began is the one observed on the host, not when the server processed the report
- **AND** the episode carries the provider, the outcome, and the number of repairs attempted as fields rather than as prose

#### Scenario: Two parts of one component failing are two episodes

- **GIVEN** a host where two capture providers owned by the same component have each exhausted recovery
- **WHEN** the server records both failures
- **THEN** each has its own open episode carrying its own provider, outcome, and attempt count
- **AND** the component recovering closes both, because the component is what an operator restores

#### Scenario: A fault whose component cannot be named is still recorded

- **GIVEN** a report of an exhausted repair that does not name the component the provider belongs to
- **WHEN** the server records the failure
- **THEN** an episode is recorded for that host
- **AND** it remains open, because no component recovery can be matched to it

#### Scenario: A redelivered report does not open a second episode

- **GIVEN** a host with an episode recorded for a reported fault
- **WHEN** the same report is delivered and processed again
- **THEN** the recorded episode is unchanged and no second episode is opened
- **AND** this holds whether that episode is still open or has already closed

#### Scenario: An episode closes when the component recovers

- **GIVEN** a host with an open episode for a component
- **WHEN** that host's status check-in reports the component healthy
- **THEN** the episode is closed, recording the instant the component was observed healthy on the host
- **AND** the record reports how long the component was in fault
- **AND** a check-in too old to update the host's current health does not close the episode either

#### Scenario: Recovery with no open episode is not an error

- **GIVEN** a host with no open episode for a component
- **WHEN** that host's status check-in reports the component healthy
- **THEN** the check-in succeeds and no episode is created or modified
