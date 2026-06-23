## MODIFIED Requirements

### Requirement: Okta OIDC is the primary login path

The system SHALL accept operator login via the configured OpenID Connect (OIDC) issuer as the primary authentication path. The provider configuration (issuer, client id, client secret, redirect URL, scopes, JIT toggle, default role) SHALL be sourced from the durable OIDC configuration store defined by the `sso-configuration` capability; `EDR_OIDC_*` environment variables act only as a first-boot bootstrap seed for that store and are not read by the login path once a stored record exists. The login flow MUST start at `GET /api/auth/login`, redirect the browser to the issuer's authorization endpoint with PKCE S256, accept the authorization-code callback at `GET /api/auth/callback`, verify the ID token's signature and standard claims (`iss`, `aud`, `exp`, `iat`, `nonce`), and exchange the resulting identity for a session cookie minted by the existing session capability. A successful callback MUST set the session cookie with `auth_method='oidc'` and redirect the browser to the application's home view. The provider/verifier the login path uses MUST reflect the current stored configuration without requiring a server restart.

#### Scenario: Operator initiates SSO login

- **GIVEN** OIDC is enabled for the deployment via a stored configuration record
- **WHEN** the browser issues `GET /api/auth/login`
- **THEN** the server responds with a 302 to the issuer's authorization endpoint
- **AND** the redirect carries the `client_id`, `redirect_url`, and scope set from the stored configuration, a server-generated `state` parameter, and a PKCE `code_challenge` with method `S256`

#### Scenario: Successful callback mints a session

- **GIVEN** the operator has authenticated at the IdP and the browser carries a fresh authorization code
- **WHEN** the IdP redirects the browser to `GET /api/auth/callback?code=...&state=...` with a matching `state`
- **THEN** the server exchanges the code, verifies the ID token, and creates a session
- **AND** the session row records `auth_method='oidc'` and the matching identity row
- **AND** the response sets the session cookie and redirects the browser to the application's home view

#### Scenario: Tampered or stale state is rejected

- **GIVEN** the IdP returns a `state` value that does not match the server-issued state cookie or whose associated state cookie has expired
- **WHEN** the callback handler verifies the state
- **THEN** the server returns a non-2xx error response without creating a session
- **AND** an audit row is recorded with decision `error` and reason `oidc.state_mismatch`

#### Scenario: A configuration change applies to the next login without restart

- **GIVEN** OIDC is enabled and an admin updates the stored issuer through the `sso-configuration` API
- **WHEN** an operator initiates `GET /api/auth/login` after the update succeeds
- **THEN** the authorization redirect targets the updated issuer's authorization endpoint with no server restart having occurred
