## ADDED Requirements

### Requirement: The API accepts a bearer access token as a second transport

The system SHALL authenticate an API request that presents a valid service-account access token in the `Authorization: Bearer` header as the bound service-account principal, alongside the existing browser transport (session cookie + CSRF). Both transports SHALL resolve to the same actor abstraction through one verification step before the authorization chokepoint, so that downstream handlers are transport-agnostic. The bearer-authenticated API boundary SHALL NOT require a CSRF token, because a bearer token is not an ambient credential and is not subject to cross-site request forgery. A request that presents neither a valid session cookie nor a valid bearer token SHALL be rejected with `401 Unauthorized`.

#### Scenario: Bearer token authenticates a service-account principal

- **GIVEN** a valid, unexpired service-account access token
- **WHEN** a request presents it in the `Authorization: Bearer` header to an API route
- **THEN** the request authenticates as the bound service-account principal
- **AND** no session cookie or CSRF token is required

#### Scenario: Cookie transport is unchanged for the browser

- **GIVEN** an operator authenticated with a session cookie
- **WHEN** the operator makes a state-changing request from the browser
- **THEN** the request still requires a valid CSRF token as before

#### Scenario: Neither credential present is unauthorized

- **WHEN** an API request presents neither a valid session cookie nor a valid bearer access token
- **THEN** the server returns `401 Unauthorized`
