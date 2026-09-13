## ADDED Requirements

### Requirement: Monitor records are reachable from the Observed count

The detection-tuning view SHALL offer, beside each rule's Observed count, a way to open that rule's monitor records. The count tells an operator how often a rule matched, and the records show what it matched, which is what promoting a rule turns on. A rule with no recorded matches, or whose counts could not be read, SHALL NOT offer the link, because it would open onto records the count gives no reason to expect.

The records view SHALL list the rule's monitor records newest first, each opening the same investigation surface an alert opens. It SHALL state that monitor records are not alerts, and SHALL explain that records collapse repeat matches on the same process and expire after a limited time, so there can be fewer records than the Observed count. Where the two numbers meet, an unexplained difference reads as lost data.

A monitor record's investigation surface SHALL NOT offer triage controls, because a monitor record has no lifecycle and the server refuses a status change on one. It SHALL say that it is a monitor record where those controls would be, and its way back SHALL lead to the rule's monitor records rather than to the alert queue, which does not list it.

#### Scenario: An operator opens the records behind a count

- **GIVEN** a rule with an Observed count on the detection-tuning view
- **WHEN** the operator follows its records link
- **THEN** the view lists that rule's monitor records, newest first, each linking to its investigation surface
- **AND** a rule that has no count, or whose counts could not be read, offers no records link

#### Scenario: The records view explains why it can show fewer than the count

- **GIVEN** the monitor records view for a rule
- **WHEN** it renders
- **THEN** it states that the records are not alerts, and that repeat matches on one process collapse and records expire, so there can be fewer records than the count

#### Scenario: A monitor record offers no triage

- **GIVEN** a monitor record opened on its investigation surface
- **WHEN** the surface renders
- **THEN** no acknowledge, resolve, or reopen control is offered, and the record is labelled as a monitor record
- **AND** its way back leads to its rule's monitor records
