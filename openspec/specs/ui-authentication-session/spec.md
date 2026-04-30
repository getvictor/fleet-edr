# UI Authentication Session Specification

## Purpose

The UI authentication session is the operator's identity boundary for the admin web interface. The same HTTP server hosts
both the agent-facing telemetry API (authenticated by per-host bearer tokens) and the operator-facing admin API
(authenticated by browser session cookies); without a clean session capability, every UI request would either need to
prompt for credentials or rely on long-lived bearer tokens stored in the browser, neither of which is acceptable for an
operator console.

The capability uses an HTTP-only session cookie that the browser cannot read from JavaScript, paired with a per-session
CSRF token that the operator's UI code reads from the login response and echoes on every state-changing request. The cookie
authenticates the request, the CSRF header proves the request originated from the legitimate UI, and the server-side row
backing the cookie can be revoked at any time by deleting the row. Sessions are persisted in the database, so restarting
the server does not invalidate them; revocation goes through the row, not the process lifecycle. The endpoints are
rate-limited and the failure paths are deliberately ambiguous about whether an account exists, so a brute-force attacker
cannot use them to enumerate operators.

## Requirements

### Requirement: Login mints a session cookie and a CSRF token

The system SHALL accept email and password on the session endpoint and on success SHALL set the session cookie and return
the CSRF token in the response body, so the UI can read the CSRF token client-side without exposing the session identifier
to JavaScript.

#### Scenario: Successful login

- **GIVEN** the client posts a valid email and password
- **WHEN** the request is processed
- **THEN** the server responds 200 with a JSON body containing the user identity and a CSRF token
- **AND** the response sets the session cookie with HttpOnly, SameSite=Lax, and (when TLS is enabled) Secure
- **AND** subsequent authenticated requests carrying that cookie are recognized as the same session

#### Scenario: Login with empty fields

- **GIVEN** the client posts an empty email or empty password
- **WHEN** the request is processed
- **THEN** the server responds 400 with a typed error
- **AND** no session is created and no cookie is set

### Requirement: Login failures do not enumerate accounts

The system MUST return the same 401 response for "no such email" and "wrong password" so an attacker cannot tell from the
response which emails correspond to real accounts, while still recording the distinction in the server-side audit log.

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

The system SHALL persist user passwords as argon2id hashes computed with time cost 3, memory cost 64 MiB, parallelism 4,
and a 32-byte derived key, using a fresh 16-byte random salt per password. The system SHALL verify the presented password
by recomputing argon2id with the stored salt under those same parameters and comparing the result to the stored hash with
a constant-time equality check. The system SHALL NOT store plaintext passwords or reversibly encrypted passwords.

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
- **AND** the per-request CPU cost is comparable to a successful login so that timing does not leak whether the password
  was the cause of the failure

### Requirement: Initial operator account is bootstrapped at first startup

The system SHALL ensure a single operator account exists when the server starts with an empty users table by generating a
random password and SHALL surface that password to the operator exactly once on the standard error stream. The system
SHALL NOT consult any environment variable to set the seeded password; the password is always randomly generated. The
seeded account uses a fixed well-known email so the operator knows where to log in. There is no in-product
password-reset flow; the documented recovery path when the password is lost is to delete the user row and restart the
server, which re-runs the seeder.

#### Scenario: First-startup seed

- **GIVEN** the server starts and the users table is empty
- **WHEN** initialization runs
- **THEN** exactly one operator account is created with the well-known seed email
- **AND** a fresh password equivalent to 24 random bytes (about 192 bits of entropy) is generated and base64url-encoded
- **AND** a banner containing the email and password is written to the standard error stream as a single write
- **AND** the password does not appear in the structured log; only the seed event with the user id and email is logged

#### Scenario: Restart with an existing operator

- **GIVEN** the users table already contains at least one row
- **WHEN** the server starts
- **THEN** no new account is created and no banner is emitted

#### Scenario: Recovery after a lost password

- **GIVEN** the captured seed banner has been lost and the operator cannot log in
- **WHEN** the operator deletes the seeded row from the users table and restarts the server
- **THEN** the seeder runs again and a new banner with a new password is written to the standard error stream

### Requirement: GET requests authenticate by cookie alone

The system SHALL authenticate safe-method (GET, HEAD, OPTIONS) requests by validating the session cookie alone, without
requiring a CSRF header.

#### Scenario: GET with valid session

- **GIVEN** the client holds a valid session cookie
- **WHEN** the client issues a GET to a session-required endpoint
- **THEN** the server identifies the user and returns the response without requiring the CSRF header

#### Scenario: GET without session

- **GIVEN** the client has no session cookie or the cookie is unrecognized
- **WHEN** the client issues a GET to a session-required endpoint
- **THEN** the server returns 401

### Requirement: Unsafe requests require both cookie and CSRF header

The system MUST require both the session cookie and a matching CSRF header on every unsafe-method (POST, PUT, DELETE)
request, and SHALL reject requests that present the cookie without a matching CSRF header.

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

The system SHALL accept a session-deletion request, remove the corresponding session row when found, and always emit a
cookie-clearing response so the browser stops sending the session cookie even if the server-side row was already gone.

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

The system SHALL expose a session-required GET that returns the currently authenticated user's identity, so the UI can
discover whether it is logged in and which account is active without re-prompting for credentials.

#### Scenario: Session probe while logged in

- **GIVEN** the client holds a valid session cookie
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 200 with the user's identity and the session's CSRF token

#### Scenario: Session probe while logged out

- **GIVEN** the client has no session cookie or the cookie is invalid
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 401

### Requirement: Login attempts are rate limited and audited

The system MUST rate limit login attempts per source IP and MUST emit an audit log entry on every failed login attempt so
operators can detect brute-force patterns.

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

The system SHALL set the session lifetime to exactly 12 hours from the moment the session row is created. The cookie's
`Expires` and `Max-Age` attributes MUST reflect that 12-hour window so the browser stops sending the cookie after it
elapses, and the server-side row MUST be treated as expired once 12 hours have passed even if the browser does send the
cookie. After expiry the operator must re-authenticate; expired sessions are not silently extended on use.

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

The system SHALL set the session cookie with HttpOnly and SameSite=Lax so JavaScript on any origin cannot read the
session identifier and a cross-site form submission cannot silently authenticate as the operator.

#### Scenario: Cookie attributes on login

- **GIVEN** the operator logs in successfully
- **WHEN** the response sets the session cookie
- **THEN** the cookie carries HttpOnly
- **AND** the cookie carries SameSite=Lax
- **AND** the cookie carries Secure when the server is configured for TLS

