# Server Identity Authentication Specification

## Purpose

This capability defines how operators authenticate to the EDR server. Okta OIDC is the primary login path, using PKCE and ID-token verification, with just-in-time provisioning of unknown SSO users onto the seeded `analyst` role. A break-glass account provides an out-of-band recovery path: it is bootstrapped via a single-use token rather than a printed password, lives behind a separate, optionally IP-allowlisted path, and requires both a local password and a WebAuthn assertion. Break-glass authentication is rate-limited tighter than SSO and audited at WARN. Destructive actions require fresh reauthentication, and the model cleanly separates a user (the person) from the identity bindings by which they authenticate.

## Requirements

### Requirement: Okta OIDC is the primary login path

The system SHALL accept operator login via the configured Okta OpenID Connect (OIDC) issuer as the primary authentication path. The login flow MUST start at `GET /api/auth/login`, redirect the browser to the issuer's authorization endpoint with PKCE S256, accept the authorization-code callback at `GET /api/auth/callback`, verify the ID token's signature and standard claims (`iss`, `aud`, `exp`, `iat`, `nonce`), and exchange the resulting identity for a session cookie minted by the existing session capability. A successful callback MUST set the session cookie with `auth_method='oidc'` and redirect the browser to the application's home view.

#### Scenario: Operator initiates SSO login

- **GIVEN** OIDC is enabled for the deployment
- **WHEN** the browser issues `GET /api/auth/login`
- **THEN** the server responds with a 302 to the issuer's authorization endpoint
- **AND** the redirect carries the configured `client_id`, the deployment's `redirect_url`, the `openid profile email` scope set, a server-generated `state` parameter, and a PKCE `code_challenge` with method `S256`

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

### Requirement: Just-in-time provisioning of unknown SSO users

The system SHALL provision a user account on first successful Okta login when `auth.oidc.allow_jit_provisioning` is enabled and no identity row exists for the incoming `(provider, subject)` pair. The newly-created user SHALL be bound to the deployment's configured default JIT role at the deployment-wide scope (the seeded `analyst` role by default, overridable to another seeded role via `EDR_OIDC_DEFAULT_ROLE`). It MUST NOT inherit any other role from claims (group to role mapping is out of scope for wave 1), and the provisioning SHALL emit an audit row with action `user.created`. When `allow_jit_provisioning` is disabled, an unknown subject SHALL be denied with an audit row whose reason is `oidc.unknown_subject`.

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

### Requirement: Break-glass account is bootstrapped via single-use token, not a printed password

The system SHALL create at most one break-glass account through a single-use bootstrap token redemption flow rather than by printing a generated password. On first boot with no users in the system, or on operator-initiated reset, the server SHALL insert a `bootstrap_tokens` row whose token bytes are stored hashed, SHALL print the redemption URL (carrying the unhashed token) once on the standard error stream, and SHALL set the token's `expires_at` to the configured `bootstrap_token_ttl`. The token SHALL be single-use; consumption MUST be atomic with the user creation it triggers.

#### Scenario: First boot with empty users prints the redemption URL

- **GIVEN** the server starts with no users
- **WHEN** initialization runs
- **THEN** the server inserts exactly one `bootstrap_tokens` row with `purpose='breakglass_setup'` and `expires_at = now + bootstrap_token_ttl`
- **AND** a banner containing the redemption URL `/admin/break-glass/setup?token=<token>` is written to the standard error stream as a single write
- **AND** the unhashed token does not appear in any structured log; only the bootstrap event with the token id and expiry is logged

#### Scenario: Token redemption sets the password and registers WebAuthn

- **GIVEN** the operator opens the redemption URL in a browser before the token expires
- **WHEN** the operator submits a password of at least 12 characters AND completes WebAuthn registration of a hardware key in the same request
- **THEN** the server creates the break-glass `users` row with `is_breakglass=1`, hashes the password with argon2id, persists the WebAuthn credential, marks the token consumed, and writes an audit row with action `auth.breakglass.bootstrap`
- **AND** the redemption response signs the operator in with a fresh break-glass session

#### Scenario: Expired or already-consumed token cannot be redeemed

- **GIVEN** a bootstrap token whose `expires_at` has passed or whose `consumed_at` is already set
- **WHEN** the operator submits the redemption form
- **THEN** the server returns a non-2xx error and does not create a user or session
- **AND** the audit log records the failed redemption with reason `bootstrap.expired` or `bootstrap.consumed`

### Requirement: Break-glass login lives at a separate path, not on the SSO login page

The system SHALL serve the ongoing break-glass login UI at `/admin/break-glass`, which MUST NOT be linked from `/login`. The break-glass login MUST require both the local password and a successful WebAuthn assertion before minting a session. When the deployment configures an IP allowlist for the break-glass path, requests originating from non-allowlisted IPs (as determined by the configured forwarded-IP header) SHALL receive `404 Not Found` so the path's existence is not acknowledged.

#### Scenario: Break-glass UI is reachable from an allowlisted IP

- **GIVEN** the requester's IP is on the configured allowlist (or no allowlist is configured)
- **WHEN** the requester issues `GET /admin/break-glass`
- **THEN** the server returns the break-glass login form (password + WebAuthn challenge)

#### Scenario: Off-allowlist requester receives 404

- **GIVEN** an IP allowlist is configured AND the requester's IP is not on it
- **WHEN** the requester issues any request to `/admin/break-glass` or `/admin/break-glass/setup`
- **THEN** the server returns `404 Not Found` with a body indistinguishable from a generic 404

#### Scenario: Successful break-glass login requires both password and WebAuthn

- **GIVEN** a requester who has supplied a correct break-glass password AND completed a WebAuthn assertion against a registered credential
- **WHEN** the server validates the submission
- **THEN** the server creates a session with `auth_method='local_password'` (with WebAuthn recorded as the second factor), sets the cookie with the break-glass tighter timeouts, and writes an audit row at WARN with action `auth.breakglass.success`

### Requirement: Break-glass authentication is rate-limited and audited at WARN

The system MUST rate-limit break-glass attempts with tighter caps than SSO login: at most 5 attempts per 15 minutes per source IP and at most 10 attempts per hour per _presented email_. The per-email limiter MUST key on the email exactly as presented in the request, regardless of whether an account exists for that email, so the response shape and timing for an unknown email are indistinguishable from those for a known email at the rate-limit layer (preventing account enumeration through differential limiter behavior). The bootstrap-setup endpoint MUST have its own rate bucket of at most 3 attempts per 5 minutes per IP. Every successful break-glass login MUST emit an audit row at WARN so a SigNoz alert can fire on any occurrence. Every failed break-glass authentication MUST emit an audit row recording the failure mode (unknown email, wrong password, WebAuthn failure) without leaking which fact caused the failure to the client.

#### Scenario: Rate limit blocks excessive attempts

- **GIVEN** a source IP has reached the per-IP cap on `/admin/break-glass`
- **WHEN** the IP issues another login attempt
- **THEN** the server returns `429 Too Many Requests` with `Retry-After`
- **AND** the user store is not consulted for that request

#### Scenario: Successful break-glass emits a WARN audit row

- **GIVEN** a successful break-glass login
- **WHEN** the response is sent
- **THEN** an audit row is recorded at level WARN with `action='auth.breakglass.success'`
- **AND** the structured slog record at WARN carries the user id, the source IP, and the request id

### Requirement: Reauthentication is required for destructive actions

The system SHALL require a fresh authentication event within the configured reauth window (default 30 minutes for normal sessions; the same window applies to break-glass sessions) before authorizing a destructive action. The set of destructive actions in wave 1 MUST include host isolation, host process kill, host script run, host enrollment revocation, and dismissing an alert whose severity is `critical`. A request whose session has not been re-authenticated within the window MUST be rejected with a typed error so the UI can prompt for re-authentication, and the rejection MUST be recorded in the audit log.

#### Scenario: Fresh session executes a destructive action

- **GIVEN** an authenticated session whose last fresh auth event is within the reauth window
- **WHEN** the operator invokes a destructive action that the policy would otherwise allow
- **THEN** the server proceeds with the action

#### Scenario: Stale session is challenged before destructive action

- **GIVEN** an authenticated session whose last fresh auth event is older than the reauth window
- **WHEN** the operator invokes a destructive action
- **THEN** the server returns a typed `reauth_required` error with the action and the reauth path
- **AND** an audit row is recorded with decision `deny` and reason `reauth_required`
- **AND** the action is not performed

### Requirement: A user is the row, an identity is the way to authenticate

The system SHALL distinguish a user (the person) from the identity binding(s) by which the user authenticates. Every user MUST have one or more identity rows; an identity row MUST belong to exactly one user. Identity kinds in wave 1 are `local_password` (used by the break-glass account) and `oidc` (used by SSO-provisioned accounts). The `(provider, subject)` pair on an identity MUST be globally unique so the same Okta account cannot bind to two users in the same deployment.

#### Scenario: SSO user has exactly one OIDC identity

- **GIVEN** a JIT-provisioned SSO user
- **WHEN** the system queries the user's identities
- **THEN** the result includes exactly one row with `kind='oidc'` keyed by the configured provider and the IdP's subject claim
- **AND** the user's `password_hash` and `password_salt` are NULL

#### Scenario: A single SSO subject cannot be bound to multiple users

- **GIVEN** a SSO callback for a subject that already has an identity bound to a different user
- **WHEN** the callback handler attempts to provision the new identity
- **THEN** the unique constraint on `(provider, subject)` rejects the bind
- **AND** the response is a non-2xx error and an audit row is recorded
