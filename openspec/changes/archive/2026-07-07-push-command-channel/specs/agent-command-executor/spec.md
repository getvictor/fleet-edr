## ADDED Requirements

### Requirement: The control connection is preferred and polling is the degraded floor

The system SHALL prefer the persistent control connection for command delivery and outcome reporting when it is established, and SHALL fall back to the polled command path only when the connection cannot be established or has dropped, so a host is never left without a command path. The polled cadence, lifecycle, and host-scoping are unchanged on the fallback path, and no additional fallback transport is introduced.

#### Scenario: Commands flow over the connection when it is up

- **GIVEN** a host holding an open control connection
- **WHEN** a command is queued for the host
- **THEN** the command is delivered and its outcome reported over the connection
- **AND** the agent does not depend on the command poll to receive or report it

#### Scenario: The poll is the fallback when the connection is unavailable

- **GIVEN** a host that cannot establish or has lost its control connection
- **WHEN** a command is queued for the host
- **THEN** the agent receives it on the polled command path at the configured interval
- **AND** acknowledges and completes it through the unchanged polled lifecycle
