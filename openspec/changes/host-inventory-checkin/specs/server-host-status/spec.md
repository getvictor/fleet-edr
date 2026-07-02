## ADDED Requirements

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
