## ADDED Requirements

### Requirement: Agent own processes view

The Processes view SHALL count the processes an agent ran for itself and offer a toggle listing them under the agent, in fork order among the session's processes, each marked as the agent's own. They SHALL be hidden until asked for, and the toggle SHALL be absent when there are none.

#### Scenario: The agent's own processes are counted and listed on request

- **GIVEN** a session whose agent ran a plugin scan and a shell snapshot with a child
- **WHEN** the operator opens the Processes view, then turns the toggle on
- **THEN** the toggle offers 3 processes and none is listed, then all 3 are listed under the agent marked "agent's own", and the session's command is not
