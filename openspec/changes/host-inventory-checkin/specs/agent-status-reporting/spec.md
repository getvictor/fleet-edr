## ADDED Requirements

### Requirement: Status report carries host inventory

The agent SHALL include a host inventory block in every status report: the kernel hostname, the OS product name, the OS product version, the OS build identifier, and the agent's own version. Inventory SHALL be collected without spawning external processes, and a field whose source is unavailable SHALL be reported empty rather than failing the report. Because the report is posted on startup, on component transitions, and on the periodic floor, a hostname rename, OS upgrade, or agent upgrade MUST be reflected in a posted report no later than one periodic interval after the agent observes it.

#### Scenario: Inventory is included in the status post

- **GIVEN** a running agent on a macOS host
- **WHEN** the agent posts a status report
- **THEN** the payload carries the hostname, OS product name, OS product version, OS build, and agent version alongside the component snapshot

#### Scenario: Missing OS metadata degrades to empty fields

- **GIVEN** an agent on a system where the OS version source is unreadable
- **WHEN** the agent posts a status report
- **THEN** the report is still posted with the unavailable OS fields empty
- **AND** the component snapshot is unaffected

### Requirement: Enrollment reports friendly OS identity

The agent's enrollment request SHALL carry the same friendly OS product version it reports in inventory, rather than a Go runtime platform token such as `darwin`.

#### Scenario: Fresh enrollment carries the OS product version

- **GIVEN** an agent enrolling on macOS
- **WHEN** it sends the enrollment request
- **THEN** the OS version field carries the OS product version (for example `26.4`), not the literal platform token `darwin`
