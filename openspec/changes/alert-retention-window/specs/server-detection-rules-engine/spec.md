## ADDED Requirements

### Requirement: Alerts expire on their own window

The system SHALL delete an alert whose last triage activity is older than a configured alert retention window. Before this, nothing deleted alerts, so an alert and the process record it pins were kept for the life of the deployment: an indefinite retention period that no one chose, and a poor answer to a framework that expects a stated one.

The alert window's default SHALL be the longest retention tier, well above the default window for derived records, because an alert is the investigation and compliance record rather than a row the server can rebuild. That default SHALL be documented as the deployment's stated alert retention policy. An operator MAY configure a shorter alert window than the derived-record window; the windows are independent, and choosing one is a policy decision this system does not second-guess.

The alert window SHALL be configured independently of the retention window for derived records, in both directions. Disabling one SHALL NOT disable, lengthen, or shorten the other: an operator who stops pruning process records to preserve a forensic window has not thereby decided anything about alerts. A window of zero SHALL disable alert pruning, which keeps the prior behaviour available to a deployment that wants it. A window too long for the system to represent SHALL be refused at startup, for both windows: accepting it and letting the arithmetic wrap would place the cutoff in the future and delete every record the window was meant to keep.

An alert's age SHALL be measured from its last triage activity, not from when it was raised. An alert an analyst acknowledged or reopened within the window is part of an investigation in progress and SHALL be kept, whenever it was first raised. A finding re-firing against an existing alert is not triage activity, so a standing condition that nobody triages still ages out, and a later re-fire raises a new alert rather than being lost. Neither is a write the system makes for its own bookkeeping, such as crediting an alert to the author of the rule that raised it: such a write SHALL NOT restart the alert's retention clock.

Deleting an alert SHALL remove its links to the events that triggered it, and SHALL do so atomically with the alert: a pass that fails part way SHALL leave every alert it did not delete with all of its evidence. A finding re-firing against an alert while that alert is being deleted SHALL complete without error, either before the deletion, in which case its evidence is deleted with the alert, or after it, in which case it raises a new alert. Neither the detection write nor the retention pass may be the casualty of the other.

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

#### Scenario: A re-fire during a prune completes cleanly

- **GIVEN** an alert past the alert window, and a finding re-firing against it that has claimed the alert but not yet linked its evidence
- **WHEN** a retention pass starts before that re-fire finishes
- **THEN** both the re-fire and the retention pass complete without error
- **AND** the alert is deleted with every event link, including the one the re-fire added

#### Scenario: Crediting an alert does not restart its retention clock

- **GIVEN** an alert whose last triage activity was long ago, and that has not yet been credited to the author of the rule that raised it
- **WHEN** the system credits it
- **THEN** the alert's last triage activity is unchanged

#### Scenario: A window too long to represent is refused at startup

- **GIVEN** an alert window or a derived-record window above the supported maximum
- **WHEN** the server starts
- **THEN** it refuses to start, naming the setting and the maximum
- **AND** a window at the maximum is accepted
