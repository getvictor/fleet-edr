## ADDED Requirements

### Requirement: Alerts expire on their own window

The system SHALL delete an alert whose last triage activity is older than a configured alert retention window. Before this, nothing deleted alerts, so an alert and the process record it pins were kept for the life of the deployment: an indefinite retention period that no one chose, and a poor answer to a framework that expects a stated one.

The alert window SHALL be the longest retention tier and SHALL default well above the window for derived records, because an alert is the investigation and compliance record rather than a row the server can rebuild. Its default SHALL be documented as the deployment's stated alert retention policy.

The alert window SHALL be configured independently of the retention window for derived records, in both directions. Disabling one SHALL NOT disable, lengthen, or shorten the other: an operator who stops pruning process records to preserve a forensic window has not thereby decided anything about alerts. A window of zero SHALL disable alert pruning, which keeps the prior behaviour available to a deployment that wants it.

An alert's age SHALL be measured from its last triage activity, not from when it was raised. An alert an analyst acknowledged or reopened within the window is part of an investigation in progress and SHALL be kept, whenever it was first raised. A finding re-firing against an existing alert is not triage activity, so a standing condition that nobody triages still ages out, and a later re-fire raises a new alert rather than being lost.

Deleting an alert SHALL remove its links to the events that triggered it, and SHALL do so atomically with the alert, so that a finding re-firing concurrently cannot attach new evidence to an alert whose earlier evidence was just removed.

An expired alert SHALL release the process record it referenced to the ordinary process prune, so a long-lived deployment does not keep process records alive solely for alerts no one can see any more. An alert inside its window SHALL continue to pin its process record, so the pivot from every visible alert keeps working.

#### Scenario: An alert past the window is pruned and one inside it survives

- **GIVEN** an alert whose last triage activity is older than the alert window, and another whose last triage activity is inside it
- **WHEN** a retention pass runs
- **THEN** the older alert and its event links are deleted
- **AND** the alert inside the window survives with all of its event links

#### Scenario: An alert raised long ago but recently triaged is kept

- **GIVEN** an alert raised long before the alert window began, and acknowledged inside it
- **WHEN** a retention pass runs
- **THEN** the alert is kept

#### Scenario: An expired alert releases the process row it pinned

- **GIVEN** a completed process record past the process window, referenced only by an alert past the alert window
- **AND** another such process record referenced by an alert inside the alert window
- **WHEN** a retention pass runs
- **THEN** the process record referenced only by the expired alert is deleted
- **AND** the process record referenced by the surviving alert is kept

#### Scenario: A disabled window prunes nothing

- **GIVEN** the alert window set to zero, and an alert of any age
- **WHEN** a retention pass runs
- **THEN** the alert is kept

#### Scenario: The alert window is independent of the process window

- **GIVEN** the process window set to zero and the alert window enabled
- **WHEN** a retention pass runs
- **THEN** alerts past the alert window are still pruned, and no process record is
- **AND** with the alert window set to zero and the process window enabled, process records are pruned and no alert is
