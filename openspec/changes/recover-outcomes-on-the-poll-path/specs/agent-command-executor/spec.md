## MODIFIED Requirements

### Requirement: The control connection is preferred and polling is the degraded floor

The system SHALL prefer the persistent control connection for command delivery and outcome reporting when it is established, and SHALL fall back to the polled command path only when the connection cannot be established or has dropped, so a host is never left without a command path. The polled cadence, lifecycle, and host-scoping are unchanged on the fallback path, and no additional fallback transport is introduced.

An outcome that did not reach the server SHALL be recoverable on the polled path as well as over the connection. The agent SHALL ask for the commands the server has acknowledged from this host and is still awaiting an outcome for, and SHALL re-report what its own ledger records for each, running no side effect. A command the ledger has no record of SHALL be left as it stands: the ledger may have been pruned or replaced, and an agent cannot tell that from a command it never ran, so reporting an outcome would invent one and running the command would repeat a side effect that was asked for once. This question MAY run on a longer interval than the poll for new work, since an outcome is already durable on the host and the answer is empty in the ordinary case.

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

#### Scenario: A lost outcome is recovered on the polled path

- **GIVEN** a host on the polled path whose command ran and whose outcome report did not reach the server
- **WHEN** the agent next asks about the commands awaiting an outcome
- **THEN** it re-reports the outcome its ledger recorded, and does not run the side effect again

#### Scenario: A command the host has no record of is left alone

- **GIVEN** a command the server is awaiting an outcome for, and an agent whose ledger has no record of it
- **WHEN** the agent asks about the commands awaiting an outcome
- **THEN** it reports nothing for that command and runs nothing, and the command keeps the status it has
