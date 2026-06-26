# SSO configuration: remove the JIT provisioning toggle delta

## MODIFIED Requirements

### Requirement: The Single sign-on admin settings page

The system SHALL present a Single sign-on settings page within the Admin settings area, reachable from the account menu and visible only to operators whose permission set includes `sso.manage`. The page SHALL render the provider configuration form (issuer, client id), an editable deployment external-URL field, a read-only redirect URL derived from the external URL (external URL + `/api/auth/callback`) with a copy affordance, the requested scopes as read-only chips, a write-only client-secret field that accepts a new value to rotate and never displays the stored secret and that opts out of password-manager capture (it holds an OIDC client secret, deployment config, not an account credential), a default-role selector restricted to Analyst and Auditor, a connection status indicator, a test-connection control, and a callout stating the break-glass account remains available if the provider is unreachable. The page SHALL NOT render a just-in-time provisioning toggle: JIT provisioning is always on, so any operator who signs in through the provider is auto-created with the default role, and the page always persists the JIT-enabled flag as true. The redirect URI registered at the IdP is the derived value; the operator maintains only the external URL. The page MUST gate its affordances on the operator's permission set returned by the session probe; the server chokepoint remains authoritative.

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
