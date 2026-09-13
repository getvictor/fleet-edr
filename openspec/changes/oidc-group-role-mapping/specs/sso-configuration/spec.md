## MODIFIED Requirements

### Requirement: Admin API reads and updates the OIDC configuration behind the chokepoint

The system SHALL expose operator API endpoints to read and update the stored OIDC configuration. Both endpoints MUST sit behind the operator-session middleware and funnel through the authorization chokepoint on the `sso.manage` action; a caller lacking that grant SHALL receive `403 Forbidden` with the chokepoint's machine-readable reason. The update endpoint MUST enforce the CSRF check required for state-changing methods, MUST validate the submitted configuration (issuer is a syntactically valid URL; when JIT is enabled a default role is present and names a seeded role; the default role is restricted to `analyst` or `auditor`; a groups claim, when present, is at most 255 characters and comes with at least one group mapping, and group mappings come only with a groups claim; each group mapping names a group of at most 255 characters that no other mapping names, and a role among `analyst`, `senior_analyst`, `auditor` and `admin`, never `super_admin`), and MUST reject an invalid submission without persisting it. The read endpoint SHALL return the groups claim and the group mappings in the order they were saved. An update SHALL replace both, like every other field.

#### Scenario: Unauthorized caller cannot read or update

- **GIVEN** an authenticated operator whose role does not grant `sso.manage`
- **WHEN** the operator requests the OIDC configuration read or update endpoint
- **THEN** the server returns `403 Forbidden` with the chokepoint reason

#### Scenario: Invalid configuration is rejected

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin submits an update whose default JIT role is `admin`
- **THEN** the server rejects the update without persisting it and returns a validation error

#### Scenario: A group mapped to super admin is rejected

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin submits an update with the groups claim `groups` and a mapping of `edr-root` to `super_admin`
- **THEN** the server rejects the update without persisting it and returns a validation error

#### Scenario: Group mappings are saved and read back

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin saves the groups claim `groups` with mappings of `edr-admins` to `admin` and `edr-auditors` to `auditor`
- **THEN** reading the configuration returns that claim and both mappings, in the order saved
