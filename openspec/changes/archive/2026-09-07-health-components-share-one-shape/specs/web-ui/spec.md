# Web UI

## MODIFIED Requirements

### Requirement: The host detail surfaces the health conditions

The web UI SHALL surface the host's agent-health rollup and per-component conditions inside the host header's Details popover rather than as a standalone panel. The Details trigger SHALL carry an attention marker (a coloured dot: amber when the rollup is degraded, red when it is unhealthy) only when the agent is not healthy, so a healthy or not-yet-reported host shows no health chrome in the always-visible header and a problem is visible at a glance without opening the popover. Opening the popover SHALL reveal the agent-health rollup as a single self-describing status pill (for example "Agent healthy" or "Agent needs attention") together with each component condition: the component, its status, a human-readable message, and how long it has been in its current state. When a required extension is not activated the message SHALL make the required action legible to an operator, for example that the security extension needs attention.

Every component SHALL be laid out the same way as every other component in the same popover. The panel is read by scanning it for the provider that is broken, and a layout that depends on how long a provider's name happens to be gives that scan a shape change carrying no information: presented as one wrapping line, a short name such as "DNS proxy" leaves room for its message beside it while longer names push theirs onto the next line, so components in one popover render in two shapes at one width. A component with no message or no recorded transition SHALL NOT leave an empty line where they would have been.

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

#### Scenario: Every component is laid out the same way

- **GIVEN** a host reporting several components whose names differ in length
- **WHEN** an operator opens the host header's Details popover
- **THEN** each component's message begins on its own line rather than beside the component's name
- **AND** every component's message begins at the same horizontal position
