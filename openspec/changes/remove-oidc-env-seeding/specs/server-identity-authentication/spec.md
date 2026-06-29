# Server Identity Authentication Specification (delta)

## MODIFIED Requirements

### Requirement: Okta OIDC is the primary login path

The system SHALL accept operator login via the configured OpenID Connect (OIDC) issuer as the primary authentication path. The provider configuration (issuer, client id, client secret, redirect URL, scopes, JIT toggle, default role) SHALL be sourced solely from the durable OIDC configuration store defined by the `sso-configuration` capability; the login path does not read any `EDR_OIDC_*` environment variable. The login flow MUST start at `GET /api/auth/login`, redirect the browser to the issuer's authorization endpoint with PKCE S256, accept the authorization-code callback at `GET /api/auth/callback`, verify the ID token's signature and standard claims (`iss`, `aud`, `exp`, `iat`, `nonce`), and exchange the resulting identity for a session cookie minted by the existing session capability. A successful callback MUST set the session cookie with `auth_method='oidc'` and redirect the browser to the application's home view. The provider/verifier the login path uses MUST reflect the current stored configuration without requiring a server restart.

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

### Requirement: Just-in-time provisioning of unknown SSO users

The system SHALL provision a user account on first successful Okta login when `auth.oidc.allow_jit_provisioning` is enabled and no identity row exists for the incoming `(provider, subject)` pair. The newly-created user SHALL be bound to the deployment's configured default JIT role at the deployment-wide scope (the seeded `analyst` role by default, overridable to another seeded role through the stored OIDC configuration's default-role field set via the Single sign-on admin API). It MUST NOT inherit any other role from claims (group to role mapping is out of scope for the current release), and the provisioning SHALL emit an audit row with action `user.created`. When `allow_jit_provisioning` is disabled, an unknown subject SHALL be denied with an audit row whose reason is `oidc.unknown_subject`.

#### Scenario: First Okta login auto-provisions an analyst

- **GIVEN** OIDC is enabled with `allow_jit_provisioning = true` and no identity row for the incoming subject
- **WHEN** the callback handler processes a verified ID token
- **THEN** the server inserts a `users` row with `password_hash = NULL` and `is_breakglass = 0`, an `identities` row keyed by `(provider, subject)`, and a `role_bindings` row to the seeded `analyst` role at the deployment-wide scope
- **AND** the audit log records `action='user.created'` with the actor identity and the resulting user id

#### Scenario: Unknown subject is rejected when JIT is disabled

- **GIVEN** OIDC is enabled with `allow_jit_provisioning = false` and no identity row for the incoming subject
- **WHEN** the callback handler processes a verified ID token
- **THEN** the server returns a non-2xx error response and does not create a user
- **AND** the audit log records the decision with reason `oidc.unknown_subject`
