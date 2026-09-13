## MODIFIED Requirements

### Requirement: Admin API reads and updates the OIDC configuration behind the chokepoint

The system SHALL expose operator API endpoints to read and update the stored OIDC configuration. Both endpoints MUST sit behind the operator-session middleware and funnel through the authorization chokepoint on the `sso.manage` action; a caller lacking that grant SHALL receive `403 Forbidden` with the chokepoint's machine-readable reason. The update endpoint MUST enforce the CSRF check required for state-changing methods, MUST validate the submitted configuration (issuer is a syntactically valid URL; when JIT is enabled a default role is present and names a seeded role; the default role is restricted to `analyst` or `auditor`; a groups claim, when present, is at most 255 characters and comes with at least one group mapping, and group mappings come only with a groups claim; each group mapping names a group of at most 255 characters that no other mapping names, and a role among `analyst`, `senior_analyst`, `auditor` and `admin`, never `super_admin`), and MUST reject an invalid submission without persisting it. The read endpoint SHALL return the groups claim and the group mappings in the order they were saved. An update SHALL replace both, like every other field. The read SHALL also return the stored configuration's version, and an update that carries the version its caller read SHALL be refused with `409 Conflict`, persisting nothing, when the stored configuration has changed since, so a client holding a stale copy cannot overwrite a newer save.

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

#### Scenario: A stale update is refused

- **GIVEN** an admin who read the configuration at one version, after which another save changed it
- **WHEN** the admin submits an update carrying the version they read
- **THEN** the server returns `409 Conflict` and the stored configuration is unchanged

#### Scenario: Group mappings are saved and read back

- **GIVEN** an admin holding `sso.manage`
- **WHEN** the admin saves the groups claim `groups` with mappings of `edr-admins` to `admin` and `edr-auditors` to `auditor`
- **THEN** reading the configuration returns that claim and both mappings, in the order saved

### Requirement: The Single sign-on admin settings page

The system SHALL present a Single sign-on settings page within the Admin settings area, reachable from the account menu and visible only to operators whose permission set includes `sso.manage`. The page SHALL render the provider configuration form (issuer, client id), an editable deployment external-URL field, a read-only redirect URL derived from the external URL (external URL + `/api/auth/callback`) with a copy affordance, the requested scopes as read-only chips, a write-only client-secret field that accepts a new value to rotate and never displays the stored secret and that opts out of password-manager capture (it holds an OIDC client secret, deployment config, not an account credential), a default-role selector restricted to Analyst and Auditor, a connection status indicator, a test-connection control, and a callout stating the break-glass account remains available if the provider is unreachable. The page SHALL NOT render a just-in-time provisioning toggle: JIT provisioning is always on, so any operator who signs in through the provider is auto-created with the default role, and the page always persists the JIT-enabled flag as true. The redirect URI registered at the IdP is the derived value; the operator maintains only the external URL. A save sends the whole configuration, so the page SHALL send back the group mapping it loaded together with the version it loaded, and when the server refuses the save because the settings were saved elsewhere since, the page SHALL say that nothing was saved and that the page must be reloaded. The page MUST gate its affordances on the operator's permission set returned by the session probe; the server chokepoint remains authoritative.

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

#### Scenario: A save after the settings changed elsewhere is refused

- **GIVEN** an admin with the Single sign-on page open, and a later save of the settings made elsewhere, such as a group mapping saved through the API
- **WHEN** the admin saves from the page
- **THEN** the page sends the version it loaded, the server refuses the save, the newer settings are unchanged, and the page says nothing was saved and to reload
