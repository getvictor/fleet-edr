## MODIFIED Requirements

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
