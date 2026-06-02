## MODIFIED Requirements

### Requirement: Login mints a session cookie and a CSRF token

The system SHALL mint a session cookie and a per-session CSRF token whenever an
authentication flow completes successfully, regardless of whether the originating flow
is the OIDC callback (handled by the server-identity-authentication capability) or the
break-glass login at `/admin/break-glass`. On success the response SHALL set the
session cookie and return the CSRF token in the response body, so the UI can read the
CSRF token client-side without exposing the session identifier to JavaScript. The
session row MUST record the `auth_method` (`oidc` or `local_password`) and, when
known, the `identity_id` of the identity that authenticated the session, so audit
queries and the UI can surface "logged in via Okta" vs "logged in via break-glass."

#### Scenario: Successful break-glass login mints a session

- **GIVEN** a break-glass operator submits a correct password and a valid WebAuthn
  assertion at `/admin/break-glass`
- **WHEN** the request is processed
- **THEN** the server responds 200 with a JSON body containing the user identity and a
  CSRF token
- **AND** the response sets the session cookie with HttpOnly, SameSite=Lax, and (when
  TLS is enabled) Secure
- **AND** the session row records `auth_method='local_password'` and the matching
  `identity_id`
- **AND** subsequent authenticated requests carrying that cookie are recognized as the
  same session

#### Scenario: Successful OIDC callback mints a session

- **GIVEN** a successful Okta callback handled by the authentication capability
- **WHEN** the callback ends
- **THEN** the response sets the session cookie with the same security attributes
- **AND** the session row records `auth_method='oidc'` and the matching `identity_id`

#### Scenario: Login with empty fields at the break-glass surface

- **GIVEN** the client posts an empty password to the break-glass login endpoint
- **WHEN** the request is processed
- **THEN** the server responds 400 with a typed error
- **AND** no session is created and no cookie is set

### Requirement: Login failures do not enumerate accounts

The system MUST return the same generic error response for "no such email" and "wrong
password" on the break-glass login surface so an attacker cannot tell from the
response which emails correspond to real accounts, while still recording the
distinction in the server-side audit log. The OIDC login surface does not face this
risk because the IdP, not the EDR, validates credentials; failures originating from
the IdP MUST surface as a generic OIDC error in the UI.

#### Scenario: Email is unknown on the break-glass surface

- **GIVEN** the client posts an email that does not correspond to any break-glass
  account
- **WHEN** the request is processed
- **THEN** the server responds 401 with a generic invalid-credentials error
- **AND** the audit log records that the email was unknown

#### Scenario: Email is known but password is wrong on the break-glass surface

- **GIVEN** the client posts an email that corresponds to a break-glass account but
  with a wrong password
- **WHEN** the request is processed
- **THEN** the server responds 401 with the same generic invalid-credentials error as
  for an unknown email
- **AND** the audit log records that the password did not match

### Requirement: Passwords are stored as argon2id hashes

The system SHALL persist user passwords as argon2id hashes computed with time cost 3,
memory cost 64 MiB, parallelism 4, and a 32-byte derived key, using a fresh 16-byte
random salt per password. The system SHALL verify the presented password by recomputing
argon2id with the stored salt under those same parameters and comparing the result to
the stored hash with a constant-time equality check. The system SHALL NOT store
plaintext passwords or reversibly encrypted passwords. SSO-authenticated users MAY
have NULL `password_hash` and `password_salt` columns; the system MUST NOT attempt to
verify a password against a NULL hash.

#### Scenario: Password verification for a break-glass account

- **GIVEN** a break-glass operator has an account with a stored argon2id hash and
  16-byte salt
- **WHEN** the operator logs in with the correct password
- **THEN** argon2id is recomputed with the stored salt under the project's parameter
  set
- **AND** the result matches the stored hash under a constant-time equality check
- **AND** the login succeeds

#### Scenario: Wrong password takes the same CPU cost as a correct one

- **GIVEN** a break-glass operator presents a known email with a wrong password
- **WHEN** the verification path runs
- **THEN** argon2id is computed under the same parameter set as a successful
  verification
- **AND** the per-request CPU cost is comparable to a successful login so that timing
  does not leak whether the password was the cause of the failure

#### Scenario: SSO user has no stored password

- **GIVEN** a user provisioned via OIDC JIT
- **WHEN** the user's row is inspected
- **THEN** `password_hash` and `password_salt` are NULL
- **AND** any code path that attempts password verification against this user errors
  out before computing argon2id

### Requirement: Initial break-glass account is bootstrapped via single-use token

The system SHALL ensure exactly one break-glass account can be created at the
deployment's first boot via a single-use bootstrap-token redemption flow, replacing
the prior "print a generated password to stderr" flow. On first boot with no users in
the system the server SHALL insert a `bootstrap_tokens` row, print the redemption URL
once on the standard error stream, and refuse logins until the token is redeemed.
Token redemption SHALL require the operator to set a password (whose strength meets
the configured policy) AND register a WebAuthn credential before the break-glass
account is created. The documented recovery path when the break-glass credentials are
lost is to invoke an operator-side reset that issues a fresh bootstrap token; deleting
a user row and restarting is no longer a valid recovery path.

#### Scenario: First-startup prints the redemption URL

- **GIVEN** the server starts and the users table is empty
- **WHEN** initialization runs
- **THEN** exactly one `bootstrap_tokens` row is inserted with
  `purpose='breakglass_setup'`
- **AND** a banner containing the redemption URL is written to the standard error
  stream as a single write
- **AND** no user row is created until the token is redeemed
- **AND** the unhashed token does not appear in the structured log; only the
  bootstrap event with the token id and expiry is logged

#### Scenario: Restart with an existing operator does not reissue a token

- **GIVEN** the users table already contains at least one row
- **WHEN** the server starts
- **THEN** no new bootstrap token is issued and no banner is emitted

#### Scenario: Recovery after a lost break-glass credential

- **GIVEN** the captured redemption URL has been lost or the WebAuthn key is
  unavailable
- **WHEN** an operator invokes the documented credential-reset procedure
- **THEN** a fresh single-use bootstrap token is issued and its redemption URL is
  printed to stderr
- **AND** the existing break-glass user row remains in place; the next redemption
  rotates its password and credential without inserting a duplicate row

### Requirement: Sessions enforce idle, absolute, and reauthentication timeouts

The system SHALL enforce three independent session lifetimes that together replace the
prior 12-hour flat expiry. A normal session MUST expire after 8 hours of idle
inactivity (sliding window) AND after 24 hours from issue (hard cap, regardless of
activity). A break-glass session MUST use tighter caps of 15 minutes idle and 1 hour
absolute. Destructive actions (host isolate, host process kill, host script run, and
critical-severity alert dismiss) MUST require a fresh authentication event within a
30-minute reauth window. The cookie's `Expires` and `Max-Age` MUST reflect the
applicable absolute timeout so the browser stops sending the cookie after it elapses,
and the server-side row MUST be treated as expired once any of the three windows has
been crossed even if the browser does send the cookie.

#### Scenario: Idle window expires a normal session

- **GIVEN** a normal session whose last activity is more than 8 hours ago but whose
  issue time is less than 24 hours ago
- **WHEN** the client uses the session cookie
- **THEN** the server treats the session as expired and returns 401

#### Scenario: Absolute window expires a normal session even with continuous use

- **GIVEN** a normal session whose issue time is more than 24 hours ago, regardless of
  activity
- **WHEN** the client uses the session cookie
- **THEN** the server treats the session as expired and returns 401

#### Scenario: Break-glass tighter caps

- **GIVEN** a session minted by the break-glass flow
- **WHEN** the cookie is set
- **THEN** the cookie's `Max-Age` reflects the 1-hour absolute cap
- **AND** the server-side row is treated as expired after 15 minutes of idle or 1 hour
  from issue, whichever comes first

#### Scenario: Reauth window challenges a destructive action

- **GIVEN** a session whose last fresh authentication event is more than 30 minutes ago
- **WHEN** the operator invokes a destructive action
- **THEN** the server returns a typed `reauth_required` error and does not perform
  the action
