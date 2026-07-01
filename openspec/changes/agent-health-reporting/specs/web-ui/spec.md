## ADDED Requirements

### Requirement: The Hosts list surfaces per-host health

The web UI SHALL show each host's overall health status in the Hosts list as a badge distinct from the existing online/offline indicator, so that a host whose sensor is not activated is visually distinguishable from a healthy host at a glance. A host whose health is unknown SHALL render a neutral badge rather than a healthy one.

#### Scenario: An unhealthy host shows a needs-attention badge

- **GIVEN** a host whose overall health status is unhealthy
- **WHEN** the Hosts list renders
- **THEN** the host's row shows a needs-attention health badge distinct from its online/offline pill

#### Scenario: A host with unknown health shows a neutral badge

- **GIVEN** a host whose overall health status is unknown
- **WHEN** the Hosts list renders
- **THEN** the host's row shows a neutral health badge and not a healthy one

### Requirement: The host detail surfaces the health conditions

The web UI host detail SHALL present the host's component conditions, each showing the component, its status, a human-readable message, and how long it has been in its current state. When a required extension is not activated the message SHALL make the required action legible to an operator, for example that the security extension needs attention.

#### Scenario: The detail lists a component with its message and age

- **GIVEN** a host whose security extension is unhealthy with a not-activated message
- **WHEN** an operator opens the host detail
- **THEN** the conditions panel shows the security extension with its unhealthy status, its message, and how long it has been in that state

#### Scenario: A fully healthy host shows all components healthy

- **GIVEN** a host whose every component is healthy
- **WHEN** an operator opens the host detail
- **THEN** the conditions panel shows each component as healthy
