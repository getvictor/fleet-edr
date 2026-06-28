## MODIFIED Requirements

### Requirement: Every configuration mutation is audited

The system SHALL emit an audit row for every successful create, update, or secret rotation of the OIDC configuration, recording the acting principal (a human user or a service account) by its principal id and a resolvable label, plus the action. The per-row attribution column (`updated_by`) SHALL store the acting principal id; a service-account update MUST record the service account's principal id rather than the interim `NULL`, and an environment-seed write with no operator SHALL record the `system` principal. The audit row MUST NOT contain the client secret in any form. Test-connection, which persists nothing, need not emit a mutation audit row.

#### Scenario: Saving a change writes an audit row naming the principal

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin saves a configuration change
- **THEN** an audit row is recorded with the acting principal id and an SSO-configuration mutation action
- **AND** the `updated_by` column stores that principal id
- **AND** the audit row contains no client-secret value

#### Scenario: A service-account update records the service-account principal, not NULL

- **GIVEN** a service account holding `sso.manage`
- **WHEN** it updates the OIDC configuration
- **THEN** the update succeeds and the `updated_by` column and audit row record the service account's principal id
- **AND** the interim behavior of recording `NULL` for a service-account updater no longer occurs
