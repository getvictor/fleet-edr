## MODIFIED Requirements

### Requirement: Authenticated entry to the application

The UI SHALL probe the server's session endpoint on application load and SHALL render
the SSO login page when the probe indicates no active session. The SSO login page MUST
present exactly one primary action — "Continue with Okta" — and MUST NOT render an
email-and-password form, MUST NOT link to the break-glass surface, and MUST NOT hint
that local login exists. Activating the SSO action MUST navigate the browser to the
server's SSO entry endpoint, which redirects to the configured Okta issuer. A
successful authentication (round-tripped through Okta and the server's callback) MUST
establish a session and route the user to the application's home view; a failed
authentication MUST surface a generic error without revealing whether the IdP rejected
the user, the EDR's JIT policy denied the user, or the callback verification failed.
The break-glass login UI lives at `/admin/break-glass` and is reachable only by
operators who know the URL out-of-band.

#### Scenario: Anonymous user lands on the SSO login page

- **GIVEN** a browser with no active session cookie
- **WHEN** the user navigates to the application
- **THEN** the UI renders the SSO login page with a single "Continue with Okta" action
- **AND** the page does not show an email or password field
- **AND** the page does not link to the break-glass surface

#### Scenario: Continue with Okta initiates the SSO flow

- **GIVEN** the SSO login page is displayed
- **WHEN** the user activates the "Continue with Okta" action
- **THEN** the browser navigates to the server's SSO entry endpoint, which redirects
  to the configured Okta issuer

#### Scenario: Successful SSO callback routes to the home view

- **GIVEN** the SSO flow has completed at the IdP and the browser has been redirected
  back to the EDR's callback endpoint with a valid authorization code
- **WHEN** the server completes its callback handling and sets the session cookie
- **THEN** the UI re-renders into the host list as the home view

#### Scenario: Failed SSO surfaces a non-revealing error

- **GIVEN** the SSO callback fails for any reason (IdP rejection, JIT policy denied
  the unknown subject, callback verification failed, network error)
- **WHEN** the UI re-renders
- **THEN** the UI shows a single generic error such as "sign-in failed; contact your
  administrator"
- **AND** the UI does not distinguish between failure modes

## ADDED Requirements

### Requirement: Account menu surfaces role and authentication method

The UI SHALL render the current operator's role and authentication method in the
account menu so an operator can tell at a glance whether they are signed in via Okta
or via the break-glass account, and what permissions their session carries. The role
label MUST be one of the seeded role names (or a custom role name if non-built-in
roles ship in a later wave). The authentication method MUST be one of `oidc` or
`local_password`. The role and authentication method MUST be visible without
navigating to a settings page; they are first-class affordances of the menu.

#### Scenario: Account menu shows Okta + analyst

- **GIVEN** an operator whose session was minted by the SSO flow and whose role
  binding is `analyst`
- **WHEN** the operator opens the account menu
- **THEN** the menu shows the operator's display name, the role label `analyst`, and
  an authentication-method indicator labelled `Okta`

#### Scenario: Account menu shows break-glass + super_admin

- **GIVEN** an operator whose session was minted via `/admin/break-glass`
- **WHEN** the operator opens the account menu
- **THEN** the menu shows the operator's display name, the role label `super_admin`,
  and an authentication-method indicator labelled `break-glass`
