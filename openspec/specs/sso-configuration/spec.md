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

The system SHALL expose operator API endpoints to read and update the stored OIDC configuration. Both endpoints MUST sit behind the authenticated API middleware (an operator session, or a service account's bearer token) and funnel through the authorization chokepoint on the `sso.manage` action; a caller lacking that grant SHALL receive `403 Forbidden` with the chokepoint's machine-readable reason. The update endpoint MUST enforce the CSRF check required for state-changing methods on a session, MUST validate the submitted configuration (issuer is a syntactically valid URL; when JIT is enabled a default role is present and names a seeded role; the default role is restricted to `analyst` or `auditor`; a groups claim, when present, is at most 255 characters and comes with at least one group mapping, and group mappings come only with a groups claim; each group mapping names a group of at most 255 characters that no other mapping names, and a role among `analyst`, `senior_analyst`, `auditor` and `admin`, never `super_admin`), and MUST reject an invalid submission without persisting it. The read endpoint SHALL return the groups claim and the group mappings in the order they were saved. An update SHALL replace both, like every other field.

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

The system SHALL emit an audit row for every successful create, update, or secret rotation of the OIDC configuration, recording the acting principal (a human user or a service account) by its principal id and a resolvable label, plus the action. The per-row attribution column (`updated_by`) SHALL store the acting principal id; a service-account update MUST record the service account's principal id rather than the interim `NULL`, and an environment-seed write with no operator SHALL record the system principal (principal id `sys`, type `system`). The audit row MUST NOT contain the client secret in any form. Test-connection, which persists nothing, need not emit a mutation audit row.

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

### Requirement: The Single sign-on admin settings page

The system SHALL present a Single sign-on settings page within the Admin settings area, reachable from the account menu and visible only to operators whose permission set includes `sso.manage`. The page SHALL render the provider configuration form (issuer, client id), an editable deployment external-URL field, a read-only redirect URL derived from the external URL (external URL + `/api/auth/callback`) with a copy affordance, the requested scopes as read-only chips with a control that adds or removes the `groups` scope and keeps every other stored scope, a write-only client-secret field that accepts a new value to rotate and never displays the stored secret and that opts out of password-manager capture (it holds an OIDC client secret, deployment config, not an account credential), a default-role selector restricted to Analyst and Auditor, a group to role mapping editor (the groups claim, and a list of group and role pairs the operator adds and removes, each role among Analyst, Senior analyst, Auditor and Admin, and no group listed twice) whose claim and mappings are saved with the rest of the configuration, a connection status indicator, a test-connection control, and a callout stating the break-glass account remains available if the provider is unreachable. The page SHALL NOT render a just-in-time provisioning toggle: JIT provisioning is always on, so any operator who signs in through the provider is auto-created with the default role, and the page always persists the JIT-enabled flag as true. The redirect URI registered at the IdP is the derived value; the operator maintains only the external URL. The page SHALL refuse to save a groups claim without a group mapping, or group mappings without a groups claim, and say which is missing. The page MUST gate its affordances on the operator's permission set returned by the session probe; the server chokepoint remains authoritative.

#### Scenario: Page is hidden from operators without the grant

- **GIVEN** an authenticated operator whose permission set does not include `sso.manage`
- **WHEN** the operator opens the account menu
- **THEN** the Admin settings entry to the Single sign-on page is not offered

#### Scenario: Secret field never shows the stored secret

- **GIVEN** a stored configuration with a client secret set
- **WHEN** an admin opens the Single sign-on page
- **THEN** the client-secret field is empty with a rotate-only affordance and the stored secret is never displayed

#### Scenario: No JIT toggle and JIT is always enabled on save

- **GIVEN** an admin on the Single sign-on page
- **WHEN** the page renders and the admin saves a configuration change
- **THEN** no just-in-time provisioning toggle is presented
- **AND** the saved configuration carries the JIT-enabled flag set to true

#### Scenario: Client-secret field opts out of password-manager capture

- **GIVEN** an admin on the Single sign-on page
- **WHEN** the client-secret field renders
- **THEN** it carries the password-manager opt-out attributes so no manager offers to save it as a login: `data-1p-ignore` and `data-form-type="other"` (1Password, Dashlane), `data-lpignore` (LastPass), `data-bwignore` (Bitwarden), and `autocomplete="off"` (the browser's built-in manager)

#### Scenario: An admin maps a group to a role from the page

- **GIVEN** an admin on the Single sign-on page with no group mapping
- **WHEN** the admin enters the groups claim `groups`, adds the group `edr-admins` with the role Admin, ticks the `groups` scope, and saves
- **THEN** the saved configuration carries the claim `groups`, the mapping of `edr-admins` to `admin`, and the stored scopes plus `groups`

#### Scenario: An incomplete group mapping is not saved

- **GIVEN** an admin on the Single sign-on page
- **WHEN** the admin adds a group mapping, leaves the groups claim empty, and saves
- **THEN** the page says the groups claim is missing and sends no update

### Requirement: A save can name the configuration it was editing

Reading the single sign-on settings SHALL report a version identifying the configuration read, and saving them SHALL accept that version back. A save that names a version SHALL be refused, having written nothing, when the stored configuration has changed since that version was issued. A save that names no version SHALL overwrite what is stored, because automation that means to set the configuration outright should not have to read it first.

The version SHALL cover every separately stored part of the configuration, and a change to any one of them SHALL supersede it. The parts are versioned separately, so a check on one leaves the others open: a save refused only for one part would still overwrite what another operator changed in another, and neither operator would learn.

A version SHALL be read from one consistent snapshot of those parts, on the read and on a save's response alike. Parts read at different moments can pair one part's new version with another's old value, describing a state that never existed; a client sending that version back would pass the check while holding stale data, which is the overwrite this prevents wearing a version number.

A version the system did not issue SHALL be refused rather than treated as absent, because treating it as absent turns the caller's conditional save into the unconditional one, and the caller is told its save was checked when it was not. A version supplied with no value is such a version: naming no version and naming an empty one mean opposite things, and a client that has a version field and nothing to put in it, which is the state a page is in before its first read completes, SHALL be refused rather than have its save promoted to an overwrite.

A version SHALL be accepted only in the spelling the system issues it in. Accepting a version that means the same number written differently would let the client and the system disagree about what a version says while the save proceeds as though they agreed.

Two saves of a configuration that does not exist yet SHALL have one winner, and the loser SHALL be told it was refused. This is the case with nothing stored to compare a version against or to lock, and it SHALL NOT be left to the isolation level to decide.

The version SHALL be opaque to clients: read it, send it back, do not take it apart.

#### Scenario: A save naming a superseded configuration is refused

- **GIVEN** an operator who read the single sign-on settings
- **AND** another operator saved a change afterwards
- **WHEN** the first operator saves, naming the version they read
- **THEN** the save is refused as a conflict
- **AND** the stored configuration is still the other operator's, unchanged

#### Scenario: A change to either stored part supersedes a version

- **GIVEN** an operator who read the single sign-on settings
- **WHEN** any single stored part of the configuration is changed by someone else
- **THEN** the version the operator read no longer matches what is stored
- **AND** a save naming it is refused

#### Scenario: Two first saves have one winner

- **GIVEN** a deployment with no single sign-on configuration stored
- **WHEN** several operators save a first configuration at the same time, each naming the version they read
- **THEN** exactly one save succeeds
- **AND** every other is refused as a conflict
- **AND** the stored configuration is one operator's, whole

#### Scenario: A version supplied with no value is refused

- **GIVEN** a client that sends a version field with nothing in it
- **WHEN** it saves
- **THEN** the save is refused as a bad request
- **AND** nothing is written

#### Scenario: A save naming no version overwrites

- **GIVEN** a script that did not read the settings
- **WHEN** it saves a configuration without naming a version
- **THEN** the save succeeds and replaces what was stored

#### Scenario: A save reports a version that matches what it saved

- **GIVEN** an operator who saves a change
- **WHEN** the save succeeds
- **THEN** it reports the version of the configuration it saved
- **AND** a further save naming that version succeeds without reading again

### Requirement: The single sign-on page saves against the configuration it was shown

The single sign-on settings page SHALL send the version of the configuration it is editing with every save, so a save that would replace a change made since the page loaded is refused rather than applied. After a successful save the page SHALL edit against the version that save returned, so an operator can save repeatedly without reloading.

A refused save SHALL be reported as what happened: that nothing was saved, that someone else changed the settings, and that reloading shows their changes. It SHALL NOT be reported as a transport status. A failure that is not a conflict SHALL continue to be reported as itself, because telling an operator to reload does not help with a problem reloading does not fix.

The page SHALL NOT offer to retry a refused save. The operator has not seen the change they would be overwriting, and offering the retry puts the overwrite one click away.

#### Scenario: The page saves against what it was shown

- **GIVEN** an operator on the single sign-on settings page
- **WHEN** they save
- **THEN** the save names the version the page was shown

#### Scenario: A second save names the first's version

- **GIVEN** an operator who has just saved
- **WHEN** they change something and save again without reloading
- **THEN** the second save names the version the first save returned

#### Scenario: A refused save says what happened

- **GIVEN** an operator whose page was open while someone else saved
- **WHEN** they save
- **THEN** they are told nothing was saved, that someone else changed the settings, and to reload
- **AND** they are not shown the transport status

### Requirement: A sign-in is judged under one configuration

A single sign-in SHALL be judged entirely under the stored configuration that verified its token. The connection settings that verify a token and the sign-in policy that judges its claims are one configuration, and they SHALL be read together: read separately, an administrator's save between the two leaves a sign-in verified under one configuration and judged under the next.

The sign-in policy is the just-in-time toggle, the default role, and the group mapping. A token from the provider being replaced being judged against a mapping written for its replacement is the sharpest form of this, because the result is the operator's role.

A configuration saved while a sign-in is in flight SHALL apply from the next sign-in. It SHALL NOT cause the sign-in in flight to be refused: the operator did nothing wrong, and a refusal is indistinguishable to them from the provider being down.

#### Scenario: A save during the exchange does not change this sign-in

- **GIVEN** an operator whose group is mapped to a role by the stored configuration
- **WHEN** they sign in, and an administrator saves a configuration without that mapping while the token exchange is in flight
- **THEN** the sign-in completes
- **AND** the operator holds the role the mapping gave them, under the configuration that verified their token
