# UI Authentication Session Specification

## Purpose

The UI authentication session is the operator's identity boundary for the admin web interface. The same HTTP server hosts both the agent-facing telemetry API (authenticated by per-host bearer tokens) and the operator-facing admin API (authenticated by browser session cookies); without a clean session capability, every UI request would either need to prompt for credentials or rely on long-lived bearer tokens stored in the browser, neither of which is acceptable for an operator console.

The capability uses an HTTP-only session cookie that the browser cannot read from JavaScript, paired with a per-session CSRF token that the operator's UI code reads from `GET /api/session` (once the cookie is set) and echoes on every state-changing request. The cookie authenticates the request, the CSRF header proves the request originated from the legitimate UI, and the server-side row backing the cookie can be revoked at any time by deleting the row. Sessions are persisted in the database, so restarting the server does not invalidate them; revocation goes through the row, not the process lifecycle. The endpoints are rate-limited and the failure paths are deliberately ambiguous about whether an account exists, so a brute-force attacker cannot use them to enumerate operators.

## Requirements

### Requirement: Login mints a session cookie and a CSRF token

The system SHALL mint a session cookie on a successful operator login. The login surface is split across two entry points:

1. **OIDC callback** at `GET /api/auth/callback`. After the operator completes the IdP redirect, the callback handler exchanges the authorization code, runs the JIT provisioner (when enabled), inserts a sessions row, and 302-redirects to the state's pinned post-login URL with the session cookie set.
2. **Break-glass finish-login** at `POST /admin/break-glass`. After the operator completes the WebAuthn assertion and the password challenge, the handler verifies the credential, inserts a sessions row, and returns 200 with the session cookie set.

Both paths set the session cookie with `HttpOnly`, `SameSite=Lax`, and (when TLS is enabled) `Secure`. The per-session CSRF token is NOT returned in the login-success response body; the UI reads it from `GET /api/session` once the cookie is set, which keeps the login-handler response shapes aligned across the two entry points. There is no `POST /api/session` password-form endpoint; sessions are minted only via the OIDC callback or the break-glass surface.

#### Scenario: Successful login

- **GIVEN** the operator completes the OIDC IdP redirect with a subject the JIT provisioner accepts
- **WHEN** the IdP's redirect lands at `/api/auth/callback` with a valid `state` cookie and authorization code
- **THEN** the server responds 302 to the state's pinned redirect (`/ui/` on the happy path) and sets the session cookie with `HttpOnly`, `SameSite=Lax`, and (when TLS is enabled) `Secure`
- **AND** subsequent authenticated requests carrying that cookie are recognized as the same session

#### Scenario: Login with empty fields

- **GIVEN** the client posts a malformed or empty body to a login endpoint (e.g., non-JSON at `POST /admin/break-glass/challenge`, or a body that omits required fields)
- **WHEN** the request is processed
- **THEN** the server responds `400 Bad Request` with a typed `X-Edr-Auth-Reason: body_invalid` header (or the endpoint-specific equivalent)
- **AND** no session is created and no cookie is set

### Requirement: Login failures do not enumerate accounts

The system MUST return the same 401 response for "no such email" and "wrong password" so an attacker cannot tell from the response which emails correspond to real accounts, while still recording the distinction in the server-side audit log.

#### Scenario: Email is unknown

- **GIVEN** the client posts an email that does not correspond to any account
- **WHEN** the request is processed
- **THEN** the server responds 401 with a generic invalid-credentials error
- **AND** the audit log records that the email was unknown

#### Scenario: Email is known but password is wrong

- **GIVEN** the client posts an email that corresponds to a real account but with a wrong password
- **WHEN** the request is processed
- **THEN** the server responds 401 with the same generic invalid-credentials error as for an unknown email
- **AND** the audit log records that the password did not match

### Requirement: Passwords are stored as argon2id hashes

The system SHALL persist user passwords as argon2id hashes computed with time cost 3, memory cost 64 MiB, parallelism 4, and a 32-byte derived key, using a fresh 16-byte random salt per password. The system SHALL verify the presented password by recomputing argon2id with the stored salt under those same parameters and comparing the result to the stored hash with a constant-time equality check. The system SHALL NOT store plaintext passwords or reversibly encrypted passwords.

#### Scenario: Password verification

- **GIVEN** an operator has an account with a stored argon2id hash and 16-byte salt
- **WHEN** the operator logs in with the correct password
- **THEN** argon2id is recomputed with the stored salt under the project's parameter set
- **AND** the result matches the stored hash under a constant-time equality check
- **AND** the login succeeds

#### Scenario: Wrong password takes the same CPU cost as a correct one

- **GIVEN** an operator presents a known email with a wrong password
- **WHEN** the verification path runs
- **THEN** argon2id is computed under the same parameter set as a successful verification
- **AND** the per-request CPU cost is comparable to a successful login so that timing does not leak whether the password was the cause of the failure

### Requirement: Initial operator account is bootstrapped at first startup

The system SHALL ensure a single operator account exists when the server starts with an empty users table by inserting a break-glass admin row (NULL password, `is_breakglass = 1`) with the well-known seed email and binding the `super_admin` role at global scope. The seed function itself MUST NOT print a password banner; the operator-facing redemption URL is logged separately by `cmd/main` on the same startup pass so the operator can complete a one-time WebAuthn enrollment that sets a password and registers a credential. There is no in-product password-reset flow; the documented recovery path when the operator loses access is to delete the seeded user row and restart the server, which re-runs the seeder and logs a new redemption URL.

#### Scenario: First-startup seed

- **GIVEN** the server starts and the users table is empty
- **WHEN** the seeder runs
- **THEN** exactly one operator account is inserted with the well-known seed email, NULL password, and `is_breakglass = 1`
- **AND** a `super_admin` role binding at global scope is inserted alongside the user row so the seeded admin has full privileges on first redemption
- **AND** the seed function does NOT write a password banner to stderr; the redemption URL is the responsibility of `cmd/main` on the same startup pass

#### Scenario: Restart with an existing operator

- **GIVEN** the users table already contains at least one row
- **WHEN** the server starts
- **THEN** no new account is created and no banner is emitted

#### Scenario: Recovery after a lost password

- **GIVEN** the operator has lost access (the redemption URL was never captured or the only enrolled credential was destroyed)
- **WHEN** the operator deletes the seeded user row and restarts the server
- **THEN** the seeder runs again, inserts a fresh break-glass admin row, and `cmd/main` logs a new redemption URL the operator can use to enrol a credential and set a password

### Requirement: GET requests authenticate by cookie alone

The system SHALL authenticate safe-method (GET, HEAD, OPTIONS) requests by validating the session cookie alone, without requiring a CSRF header.

#### Scenario: GET with valid session

- **GIVEN** the client holds a valid session cookie
- **WHEN** the client issues a GET to a session-required endpoint
- **THEN** the server identifies the user and returns the response without requiring the CSRF header

#### Scenario: GET without session

- **GIVEN** the client has no session cookie or the cookie is unrecognized
- **WHEN** the client issues a GET to a session-required endpoint
- **THEN** the server returns 401

### Requirement: Unsafe requests require both cookie and CSRF header

The system MUST require both the session cookie and a matching CSRF header on every unsafe-method (POST, PUT, DELETE) request, and SHALL reject requests that present the cookie without a matching CSRF header.

#### Scenario: POST with cookie but no CSRF header

- **GIVEN** the client holds a valid session cookie but sends no CSRF header
- **WHEN** the client issues a POST to a session-required endpoint
- **THEN** the server returns 403 with a typed CSRF-missing error
- **AND** the request's side effects are not performed

#### Scenario: POST with mismatched CSRF header

- **GIVEN** the client sends a CSRF header whose value does not match the session's stored CSRF token
- **WHEN** the request is processed
- **THEN** the server returns 403 with a typed CSRF-mismatch error
- **AND** the comparison uses a constant-time equality check

#### Scenario: POST with valid cookie and CSRF header

- **GIVEN** the client sends both a valid session cookie and the matching CSRF header
- **WHEN** the request is processed
- **THEN** the server identifies the user and performs the action

### Requirement: Logout invalidates the session and clears the cookie

The system SHALL accept a session-deletion request, remove the corresponding session row when found, and always emit a cookie-clearing response so the browser stops sending the session cookie even if the server-side row was already gone.

#### Scenario: Logout while logged in

- **GIVEN** the client holds a valid session cookie
- **WHEN** the client issues the session-deletion request
- **THEN** the server removes the session row and returns a cookie-clearing response with status 204
- **AND** subsequent requests with the previous cookie value are treated as unauthenticated

#### Scenario: Logout with stale or missing cookie

- **GIVEN** the client's cookie no longer corresponds to any active session row
- **WHEN** the client issues the session-deletion request
- **THEN** the server still emits the cookie-clearing response with status 204
- **AND** the client's browser stops sending the dead cookie value

### Requirement: Current-user lookup

The system SHALL expose a session-required GET that returns the currently authenticated operator's identity AND the operator's effective permission set, so the UI can discover whether it is logged in, which account is active, and which privileged actions the operator may perform, without re-prompting for credentials and without a per-action round trip. The effective permission set SHALL be the collection of action identifiers the operator is permitted under the active session's role bindings at the deployment-wide scope, evaluated consistently with the authorization decision the server enforces. A role that grants every action SHALL be expanded to the concrete action identifiers rather than returning a wildcard token. The permission set SHALL be present for every authenticated session regardless of whether it was established via SSO or via the break-glass surface. The permission set is advisory to the UI for presentation only; no client SHALL treat it as authorization, and the server SHALL continue to enforce every action at its authorization boundary independently of what the permission set contained.

#### Scenario: Session probe while logged in

- **GIVEN** the client holds a valid session cookie for an operator bound to the `analyst` role
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 200 with the operator's identity, the session's CSRF token, and a permission set containing the analyst actions (for example `host.read`, `process.read`, `alert.read`, `alert.comment`)
- **AND** the permission set does not contain `host.kill_process` or `application_control.read`

#### Scenario: Higher-privilege role returns a superset

- **GIVEN** the client holds a valid session for an operator bound to `senior_analyst`
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the returned permission set additionally contains `host.kill_process`, `host.isolate`, `host.run_script`, and `application_control.read`

#### Scenario: All-actions role is expanded rather than wildcarded

- **GIVEN** the client holds a valid session for an operator whose role grants every action
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the returned permission set lists the concrete action identifiers from the action registry
- **AND** it does not contain a wildcard token such as `*`

#### Scenario: Session probe while logged out

- **GIVEN** the client has no session cookie or the cookie is invalid
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 401 and no permission set is returned

### Requirement: Login attempts are rate limited and audited

The system MUST rate limit login attempts per source IP and MUST emit an audit log entry on every failed login attempt so operators can detect brute-force patterns.

#### Scenario: Excess login attempts from one IP

- **GIVEN** an IP has exceeded the configured per-minute login attempt cap
- **WHEN** the IP issues another login attempt
- **THEN** the server returns 429 with a Retry-After header
- **AND** the user store is not consulted for that request

#### Scenario: Failed login is audited

- **GIVEN** a login attempt fails for any reason (unknown email, wrong password, rate limit, internal)
- **WHEN** the response is sent
- **THEN** an audit log line is emitted including the source IP, the presented email, and a typed reason
- **AND** the audit line does not include the presented password

### Requirement: Sessions expire 12 hours after issue

The system SHALL set the session lifetime to exactly 12 hours from the moment the session row is created. The cookie's `Expires` and `Max-Age` attributes MUST reflect that 12-hour window so the browser stops sending the cookie after it elapses, and the server-side row MUST be treated as expired once 12 hours have passed even if the browser does send the cookie. After expiry the operator must re-authenticate; expired sessions are not silently extended on use.

#### Scenario: Cookie carries a 12-hour expiry on login

- **GIVEN** the operator logs in successfully
- **WHEN** the response sets the session cookie
- **THEN** the cookie's `Expires` attribute is exactly 12 hours after the issue time
- **AND** the cookie's `Max-Age` attribute reflects the same 12-hour window in seconds

#### Scenario: A request after the 12-hour window is rejected

- **GIVEN** a session cookie that was issued more than 12 hours ago
- **WHEN** the client uses that cookie on any session-required endpoint
- **THEN** the server treats the session as expired and returns 401
- **AND** the request is not authenticated as the original operator

### Requirement: Session cookie is HTTP-only and same-site

The system SHALL set the session cookie with HttpOnly and SameSite=Lax so JavaScript on any origin cannot read the session identifier and a cross-site form submission cannot silently authenticate as the operator.

#### Scenario: Cookie attributes on login

- **GIVEN** the operator logs in successfully
- **WHEN** the response sets the session cookie
- **THEN** the cookie carries HttpOnly
- **AND** the cookie carries SameSite=Lax
- **AND** the cookie carries Secure when the server is configured for TLS
