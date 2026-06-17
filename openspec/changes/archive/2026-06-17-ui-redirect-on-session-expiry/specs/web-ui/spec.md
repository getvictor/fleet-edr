# Web UI Specification (delta)

## MODIFIED Requirements

### Requirement: Authenticated entry to the application

The UI SHALL probe the server's session endpoint on application load and SHALL render the login page when the probe indicates no active session. A successful login MUST establish a session and route the user to the application's home view; an invalid login MUST surface a generic error without revealing whether the email or the password was wrong. When the session lapses while the app is already open (an idle or absolute timeout, or a server-side revocation) and any subsequent request to the server is rejected as unauthenticated, the UI MUST return the operator to the login page rather than leaving them on a page that renders a raw transport error such as `API error: 401`. The redirect SHALL preserve the operator's current location so a successful re-login returns them to where they were.

The change from the prior requirement is the addition of the mid-session expiry behavior: redirect-to-login is no longer limited to the load-time probe; a 401 on any later request also returns the operator to login.

#### Scenario: Anonymous user lands on the login page

- **GIVEN** a browser with no active session cookie
- **WHEN** the user navigates to the application
- **THEN** the UI renders the login page with the configured sign-in controls (SSO and a break-glass entry point)

#### Scenario: Successful login routes to the home view

- **GIVEN** the login page is displayed
- **WHEN** the user submits a valid email and password
- **THEN** the server establishes a session and the UI re-renders into the host list as the home view

#### Scenario: Failed login shows a non-enumerating error

- **GIVEN** the login page is displayed
- **WHEN** the user submits credentials the server rejects
- **THEN** the UI shows a single generic error such as "invalid email or password"
- **AND** the UI does not distinguish between unknown email and wrong password

#### Scenario: Mid-session expiry returns the operator to login

- **GIVEN** an authenticated operator viewing any page after the load-time session probe has already succeeded
- **WHEN** a subsequent request to the server is rejected as unauthenticated because the session has expired or been revoked
- **THEN** the UI returns the operator to the login page rather than rendering a raw `API error: 401` on the current page
- **AND** the operator's current location is preserved so a successful re-login returns them to where they were
