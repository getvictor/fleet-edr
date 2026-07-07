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
