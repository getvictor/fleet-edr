## MODIFIED Requirements

### Requirement: The host detail surfaces the health conditions

The web UI SHALL surface the host's agent-health rollup and per-component conditions inside the host header's Details popover rather than as a standalone panel. The Details trigger SHALL carry an attention marker (a coloured dot: amber when the rollup is degraded, red when it is unhealthy) only when the agent is not healthy, so a healthy or not-yet-reported host shows no health chrome in the always-visible header and a problem is visible at a glance without opening the popover. Opening the popover SHALL reveal the agent-health rollup as a single self-describing status pill (for example "Agent healthy" or "Agent needs attention") together with each component condition: the component, its status, a human-readable message, and how long it has been in its current state. When a required extension is not activated the message SHALL make the required action legible to an operator, for example that the security extension needs attention.

#### Scenario: The detail lists a component with its message and age

- **GIVEN** a host whose security extension is unhealthy with a not-activated message
- **WHEN** an operator opens the host header's Details popover
- **THEN** the popover shows the security extension with its unhealthy status, its message, and how long it has been in that state
- **AND** the Details trigger carried an attention dot before it was opened

#### Scenario: A fully healthy host shows a single healthy rollup

- **GIVEN** a host whose every component is healthy
- **WHEN** the operator views the host header
- **THEN** the Details trigger shows no attention dot
- **AND** opening the popover reveals a single "Agent healthy" status pill and the per-component conditions

## ADDED Requirements

### Requirement: The process detail omits a self-referential alert link

When the process detail panel is opened from an alert's page, its "Related alerts" references SHALL omit the alert whose page is currently open, so the panel never links back to the page the operator is already on. Every other alert on the process SHALL still be listed. When the panel is opened outside an alert context, every alert on the process SHALL be listed.

#### Scenario: Related alerts omit the alert whose page is open

- **GIVEN** a process has two alerts and the operator is on one of those alert's pages
- **WHEN** the process detail panel lists the process's Related alerts
- **THEN** the alert whose page is open is omitted from the list
- **AND** the process's other alert is still shown as a link to its alert page

### Requirement: The process tree hides the system-noise toggle when it changes nothing

The process tree's "Show system" toggle (which reveals system-path processes hidden by default) SHALL be offered only when flipping it would change the rendered tree. When the current view has no hidden system-path process to reveal (for example an alert chain whose only system-path nodes are the alerted process and its ancestors, which are shown regardless), the toggle SHALL NOT be rendered, so the operator is never presented with a control that does nothing.

#### Scenario: The toggle is hidden when there is no system noise to reveal

- **GIVEN** a process tree whose visible nodes include no system-path process that is hidden by default
- **WHEN** the tree renders
- **THEN** the "Show system" toggle is not shown

#### Scenario: The toggle is shown when system processes are hidden

- **GIVEN** a process tree that contains a system-path process hidden by default
- **WHEN** the tree renders
- **THEN** the "Show system" toggle is shown so the operator can reveal it

### Requirement: The kill action is disabled once the process has exited

The process detail panel's "Kill process" control SHALL be disabled when the process has already exited, because a kill targets a live PID and after exit that PID is either free or reused by an unrelated process, so a kill-by-pid could terminate the wrong process. The disabled control SHALL make the reason legible (that the process has already exited).

#### Scenario: An exited process cannot be killed from the detail panel

- **GIVEN** a process whose detail panel is open and which has an exit time
- **WHEN** the operator views the "Kill process" control
- **THEN** the control is disabled and indicates that the process has already exited
- **AND** activating it dispatches no kill command
