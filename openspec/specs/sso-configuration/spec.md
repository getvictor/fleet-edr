# sso-configuration Specification

## Purpose

Defines how the OIDC single sign-on configuration is stored durably as the runtime source of truth, seeded from environment variables on first boot only, read and updated through an audited admin surface behind the authorization chokepoint, applied without a server restart, and protected (write-only client secret encrypted at rest, connection test without persisting).

## Requirements

### Requirement: OIDC configuration is stored durably and is the runtime source of truth

The system SHALL persist the deployment's OIDC provider configuration (issuer URL, client id, client secret, requested scopes, JIT-provisioning enabled flag, default JIT role) in MySQL as a single deployment-wide configuration record. The OIDC redirect URI is NOT stored: it is derived from the deployment external URL (persisted in the general app-config document) as external URL + `/api/auth/callback`. When a stored configuration record exists, the OIDC login flow SHALL derive its issuer, client id, client secret, scopes, JIT toggle, and default role from that record, and its redirect URI from the stored external URL, rather than from any in-process value captured at boot. The store is the single source of truth so that every replica serves a consistent configuration and a configuration change survives a restart.

#### Scenario: Login flow reads the stored configuration

- **GIVEN** a stored OIDC configuration record exists with a given issuer and client id
- **WHEN** an operator initiates SSO login
- **THEN** the authorization redirect carries the client id from the stored record and a redirect URL derived from the stored external URL, not from any environment variable

#### Scenario: Stored configuration survives a restart

- **GIVEN** an admin has saved an OIDC configuration through the API
- **WHEN** the server process restarts with no `EDR_OIDC_*` environment variables set
- **THEN** the OIDC login flow remains enabled using the stored configuration

### Requirement: Environment variables seed the stored configuration on first boot only

The system SHALL treat `EDR_OIDC_*` environment variables as a one-time bootstrap seed: on boot, when no stored OIDC configuration record exists and the env block is set, the server SHALL create the stored record from the env values. When a stored record already exists, the server SHALL NOT apply env values; it MUST treat the stored record as authoritative and MAY log once that env values are present but inert. This preserves existing env-only deployments on upgrade while making the stored record the governing source thereafter.

#### Scenario: First boot seeds the record from env

- **GIVEN** no stored OIDC configuration record exists
- **AND** the `EDR_OIDC_*` environment block is fully set
- **WHEN** the server boots
- **THEN** a stored OIDC configuration record is created from the env values
- **AND** subsequent SSO logins use the stored record

#### Scenario: Env values are inert once a record exists

- **GIVEN** a stored OIDC configuration record exists with one issuer
- **AND** the `EDR_OIDC_ISSUER` environment variable is set to a different issuer
- **WHEN** the server boots
- **THEN** the stored record is unchanged and the login flow uses the stored issuer

### Requirement: Configuration changes apply without a server restart

The system SHALL apply a saved OIDC configuration change to the live login flow without requiring a restart. After a successful update, a newly initiated login SHALL use the updated configuration. Because the deployment is multi-replica and stateless (no shared in-process state that a peer would need), each replica SHALL refresh its view of the configuration from the durable store; any in-process provider client a replica holds is a per-replica cache that is safe to lose and is rebuilt from the stored record when the record changes.

#### Scenario: A saved change takes effect on the next login

- **GIVEN** an admin updates the stored issuer through the API
- **WHEN** an operator initiates SSO login after the update returns success
- **THEN** the authorization redirect targets the updated issuer's authorization endpoint
- **AND** no server restart was required

### Requirement: The client secret is encrypted at rest and write-only over the API

The system SHALL store the OIDC client secret encrypted at rest using a key derived from the deployment root secret (`EDR_SECRET_KEY`) under a dedicated HKDF label, never as plaintext in the database. The configuration read API MUST NOT return the client secret in any form (not even masked-but-reversible); it MAY return only a boolean indicating whether a secret is set. The update API SHALL accept a new secret value to rotate it; an update that omits the secret field SHALL leave the stored secret unchanged.

#### Scenario: Read never returns the secret

- **WHEN** an admin reads the OIDC configuration through the API
- **THEN** the response contains no client-secret value
- **AND** the response indicates whether a secret is currently set

#### Scenario: Update rotates the secret only when provided

- **GIVEN** a stored configuration with an existing client secret
- **WHEN** an admin submits an update that omits the client-secret field
- **THEN** the stored secret is left unchanged
- **AND** when the admin submits an update that includes a new client-secret value, the stored secret is replaced with the new value encrypted at rest

### Requirement: Admin API reads and updates the OIDC configuration behind the chokepoint

The system SHALL expose operator API endpoints to read and update the stored OIDC configuration. Both endpoints MUST sit behind the operator-session middleware and funnel through the authorization chokepoint on the `sso.manage` action; a caller lacking that grant SHALL receive `403 Forbidden` with the chokepoint's machine-readable reason. The update endpoint MUST enforce the CSRF check required for state-changing methods, MUST validate the submitted configuration (issuer is a syntactically valid URL; when JIT is enabled a default role is present and names a seeded role; the default role is restricted to `analyst` or `auditor`), and MUST reject an invalid submission without persisting it.

#### Scenario: Unauthorized caller cannot read or update

- **GIVEN** an authenticated operator whose role does not grant `sso.manage`
- **WHEN** the operator requests the OIDC configuration read or update endpoint
- **THEN** the server returns `403 Forbidden` with the chokepoint reason

#### Scenario: Invalid configuration is rejected

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin submits an update whose default JIT role is `admin`
- **THEN** the server rejects the update without persisting it and returns a validation error

### Requirement: Test-connection probes the provider without persisting

The system SHALL expose a test-connection action, gated on `sso.manage`, that validates a candidate OIDC configuration by fetching the issuer's discovery document and confirming the advertised token endpoint is reachable, and returns a pass/fail result with a diagnostic reason on failure. The test-connection action MUST NOT persist any configuration; it operates on the submitted candidate (or the stored record) purely to verify reachability before an admin saves.

#### Scenario: Reachable provider verifies

- **GIVEN** an admin submits a candidate issuer whose discovery document and token endpoint are reachable
- **WHEN** the admin invokes test-connection
- **THEN** the server returns a success result
- **AND** no configuration is persisted by the call

#### Scenario: Unreachable provider fails with a reason

- **GIVEN** an admin submits a candidate issuer whose discovery document cannot be fetched
- **WHEN** the admin invokes test-connection
- **THEN** the server returns a failure result carrying a diagnostic reason

### Requirement: Every configuration mutation is audited

The system SHALL emit an audit row for every successful create, update, or secret rotation of the OIDC configuration, recording the acting operator's user id and the action. The audit row MUST NOT contain the client secret in any form. Test-connection, which persists nothing, need not emit a mutation audit row.

#### Scenario: Saving a change writes an audit row

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin saves a configuration change
- **THEN** an audit row is recorded with the acting user id and an SSO-configuration mutation action
- **AND** the audit row contains no client-secret value

### Requirement: The Single sign-on admin settings page

The system SHALL present a Single sign-on settings page within the Admin settings area, reachable from the account menu and visible only to operators whose permission set includes `sso.manage`. The page SHALL render the provider configuration form (issuer, client id), an editable deployment external-URL field, a read-only redirect URL derived from the external URL (external URL + `/api/auth/callback`) with a copy affordance, the requested scopes as read-only chips, a write-only client-secret field that accepts a new value to rotate and never displays the stored secret, a just-in-time provisioning toggle, a default-role selector restricted to Analyst and Auditor, a connection status indicator, a test-connection control, and a callout stating the break-glass account remains available if the provider is unreachable. The redirect URI registered at the IdP is the derived value; the operator maintains only the external URL. The page MUST gate its affordances on the operator's permission set returned by the session probe; the server chokepoint remains authoritative.

#### Scenario: Page is hidden from operators without the grant

- **GIVEN** an authenticated operator whose permission set does not include `sso.manage`
- **WHEN** the operator opens the account menu
- **THEN** the Admin settings entry to the Single sign-on page is not offered

#### Scenario: Secret field never shows the stored secret

- **GIVEN** a stored configuration with a client secret set
- **WHEN** an admin opens the Single sign-on page
- **THEN** the client-secret field is empty with a rotate-only affordance and the stored secret is never displayed
