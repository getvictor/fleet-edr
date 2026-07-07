# server-host-status Specification

## Purpose

The server accepts a host-token-authenticated status check-in, persists the latest health snapshot per host as last-writer-wins, and validates component status against a closed set while storing unrecognized component types and reasons verbatim, so an operator can see current per-host agent and extension health.

## Requirements

### Requirement: The server accepts and persists a host status snapshot

The server SHALL expose a host-token-authenticated check-in that accepts a status snapshot carrying the agent version and a list of component conditions, and SHALL persist the latest snapshot per host as last-writer-wins keyed on the host. A snapshot from an unauthenticated or invalidly-authenticated caller SHALL be rejected. The server SHALL validate the component status against the closed set `healthy`, `degraded`, `unhealthy`, `unknown` and reject a snapshot carrying any other status value, while accepting component `type` and `reason` values it does not recognize and storing them verbatim.

#### Scenario: A valid snapshot is stored as the latest health for the host

- **GIVEN** an enrolled host with a valid host token
- **WHEN** it posts a snapshot with two components
- **THEN** the server stores that snapshot as the host's current health

#### Scenario: A later snapshot replaces an earlier one

- **GIVEN** a host that has already posted a snapshot
- **WHEN** it posts a newer snapshot for the same host
- **THEN** the server's stored health reflects the newer snapshot and not the earlier one

#### Scenario: An unknown component type is stored verbatim

- **GIVEN** a valid host token
- **WHEN** the host posts a snapshot containing a component whose type the server does not recognize but whose status is in the closed set
- **THEN** the snapshot is accepted and the unknown component is stored and returned unchanged

#### Scenario: An invalid status value is rejected

- **WHEN** a host posts a snapshot whose component status is not in the closed set
- **THEN** the server rejects the snapshot and stores nothing

#### Scenario: An unauthenticated check-in is rejected

- **WHEN** a caller posts a snapshot without a valid host token
- **THEN** the server rejects the request and stores nothing

### Requirement: The server computes an overall host-health rollup

The server SHALL derive an overall health status for each host from its component conditions as the worst condition present: `unhealthy` if any component is unhealthy, otherwise `degraded` if any component is degraded, otherwise `healthy` if at least one component is present, otherwise `unknown`. The agent SHALL NOT supply the overall status; it is computed on the server from the stored components.

#### Scenario: One unhealthy component makes the host unhealthy

- **GIVEN** a host whose network extension is healthy and whose security extension is unhealthy
- **WHEN** the rollup is computed
- **THEN** the host's overall status is `unhealthy`

#### Scenario: A host with no snapshot rolls up to unknown

- **GIVEN** a host that has never posted a snapshot
- **WHEN** the host's overall status is read
- **THEN** it is `unknown`

#### Scenario: All-healthy components roll up to healthy

- **GIVEN** a host whose every component is healthy
- **WHEN** the rollup is computed
- **THEN** the host's overall status is `healthy`

### Requirement: The host API surfaces per-host health

An operator holding host read access SHALL see each host's overall health status in the host list, and SHALL see the full list of component conditions in the single-host detail. A host without a stored snapshot SHALL appear in the list with overall status `unknown` rather than being omitted.

#### Scenario: The host list carries the overall status

- **GIVEN** an operator with host read access and a host with a stored snapshot
- **WHEN** they read the host list
- **THEN** the host's row carries its computed overall health status

#### Scenario: The host detail carries the component conditions

- **GIVEN** an operator with host read access and a host with a stored snapshot
- **WHEN** they read that host's detail
- **THEN** the response carries each component's type, status, reason, message, and last-transition timestamp

#### Scenario: A host with no snapshot still lists with unknown health

- **GIVEN** a host that has sent events but never posted a snapshot
- **WHEN** an operator reads the host list
- **THEN** the host appears with overall status `unknown`

### Requirement: Server persists inventory from the status check-in

When an accepted status report carries a host inventory block, the server SHALL persist the reported hostname, OS product name, OS product version, OS build, and the report's agent version onto the host's identity record, together with the report's timestamp, so the identity record reflects the latest check-in rather than the enrollment-time snapshot. A status report that carries no inventory block MUST leave the identity record untouched, and an empty field inside a present inventory block MUST preserve the previously recorded value rather than overwrite it (an empty claim means the agent's source was unavailable, and a degraded collector must not blank known identity). Inventory persistence MUST NOT change the health snapshot semantics: a report with invalid component status is rejected as a whole, including its inventory.

#### Scenario: Check-in refreshes identity after an OS upgrade

- **GIVEN** an enrolled host whose enrollment recorded OS version `26.3`
- **WHEN** the agent posts a status report whose inventory carries OS version `26.4`
- **THEN** the host's identity record reports OS version `26.4` without a re-enrollment

#### Scenario: Report without inventory leaves identity untouched

- **GIVEN** an enrolled host with recorded identity fields
- **WHEN** an agent posts a status report that omits the inventory block (an older agent)
- **THEN** the report's health snapshot is stored
- **AND** the identity record is unchanged

#### Scenario: Empty inventory fields preserve recorded identity

- **GIVEN** an enrolled host whose identity record holds OS version `26.4` from a prior check-in
- **WHEN** the agent posts a status report whose inventory carries a non-empty hostname but empty OS fields (a degraded collector)
- **THEN** the hostname is refreshed
- **AND** the recorded OS fields are preserved, not blanked

#### Scenario: Rejected report does not write inventory

- **GIVEN** a status report whose component snapshot carries an invalid status value and whose inventory carries a new hostname
- **WHEN** the server processes the report
- **THEN** the report is rejected
- **AND** the identity record is unchanged
