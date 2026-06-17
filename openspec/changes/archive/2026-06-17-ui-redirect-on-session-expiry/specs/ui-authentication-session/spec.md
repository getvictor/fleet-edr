# UI Authentication Session Specification (delta)

## ADDED Requirements

### Requirement: Sessions expire on idle and absolute timeouts per class

The system SHALL bound every session by two timeouts: an idle timeout measured from the last activity and an absolute timeout measured from session creation. The pair is chosen by session class. Normal (SSO/OIDC) sessions use the lenient pair: idle 8 hours, absolute 24 hours. Break-glass (local-password) sessions use the strict pair: idle 15 minutes, absolute 1 hour, so a stolen recovery cookie expires before the end of an incident shift. The absolute cap SHALL be pinned at mint time (stored on the session row) so a later configuration change does not retroactively extend or shorten existing sessions. The session cookie's `Expires` and `Max-Age` attributes SHALL reflect the absolute cap so the browser stops sending the cookie once it elapses. The idle timeout SHALL slide on use: activity within the idle window extends the session, but never past the absolute cap. A request whose session has crossed either timeout MUST be treated as expired and rejected with 401; a session past its absolute cap is never extended on use.

#### Scenario: Cookie carries the absolute timeout on login

- **GIVEN** the operator logs in successfully
- **WHEN** the response sets the session cookie
- **THEN** the cookie's `Expires` attribute equals the session's absolute expiry (creation time plus the class's absolute timeout)
- **AND** the cookie's `Max-Age` attribute is the number of seconds remaining until that expiry

#### Scenario: A request after the absolute cap is rejected

- **GIVEN** a session whose absolute cap has elapsed
- **WHEN** the client uses that session cookie on any session-required endpoint
- **THEN** the server treats the session as expired and returns 401
- **AND** the request is not authenticated as the original operator

#### Scenario: A request after the idle window is rejected

- **GIVEN** a session that is still within its absolute cap but whose last activity is older than the class's idle timeout
- **WHEN** the client uses that session cookie on any session-required endpoint
- **THEN** the server treats the session as expired and returns 401

#### Scenario: Activity within the idle window slides the session

- **GIVEN** a session whose operator keeps interacting within the idle window
- **WHEN** each request advances the session's last-activity time
- **THEN** the session stays valid past what would otherwise be the idle-timeout cutoff
- **AND** the session is still rejected once the absolute cap elapses, regardless of activity

#### Scenario: Break-glass sessions use the strict timeout pair

- **GIVEN** a session minted through the break-glass surface (`auth_method='local_password'`)
- **WHEN** its idle gate is evaluated
- **THEN** the strict break-glass pair applies (15-minute idle, 1-hour absolute), not the normal pair

## REMOVED Requirements

### Requirement: Sessions expire 12 hours after issue

**Reason**: The flat 12-hour-from-issue model never matched the implementation, which bounds each session by a class-specific idle + absolute timeout pair (`sessions.Timeouts`: normal 8h/24h, break-glass 15m/1h) with a sliding idle window. The drift was tracked in #257 and acknowledged in the test markers. This change reconciles the canonical spec to the shipped behavior; the replacement requirement "Sessions expire on idle and absolute timeouts per class" carries the accurate contract.

**Migration**: None. This is a documentation reconciliation of already-shipped behavior, not a behavior change. The existing tests already pinned the real idle/absolute/sliding/per-class behavior; their spec markers are repointed to the new scenarios in the same change.
