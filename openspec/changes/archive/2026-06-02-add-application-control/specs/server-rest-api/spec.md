# Server REST API Specification (delta)

## ADDED Requirements

### Requirement: Application control endpoints under /api/v1/app-control/

The system SHALL expose the application control subsystem under the URL prefix `/api/v1/app-control/` with
the same session-cookie + CSRF authentication as the rest of this capability. The endpoints SHALL include
listing, fetching, creating, updating, and deleting application control policies; creating, updating, and
deleting rules within a policy; idempotent bulk upsert of rules within a policy; listing rules across
policies with filter parameters; CRUD on host groups; and creating policy → host-group assignments. The
detailed shapes, validation, audit, and fan-out behavior of these endpoints belong to the
`server-application-control` capability; this capability covers their authentication, CSRF protection, and
error-shape conformance.

#### Scenario: An unauthenticated request to an app-control endpoint is rejected

- **GIVEN** a client that does not present a valid `edr_session` cookie
- **WHEN** the client calls any endpoint under `/api/v1/app-control/`
- **THEN** the system responds with HTTP 401 and the standard `ErrorResponse` body
- **AND** no application-control data is returned

#### Scenario: A state-changing app-control call without CSRF is rejected

- **GIVEN** a client with a valid session cookie but no matching CSRF token header
- **WHEN** the client issues `POST /api/v1/app-control/policies`
- **THEN** the system responds with HTTP 403 and the standard `ErrorResponse` body
- **AND** no policy is created

#### Scenario: A failure response uses the standard error shape

- **GIVEN** an authenticated operator who submits an invalid rule identifier
- **WHEN** the server rejects the request
- **THEN** the response body is a JSON object with an `error` field carrying a stable typed error code
- **AND** the typed code unambiguously identifies the invalidity (for example
  `application_control.invalid_identifier`)

## REMOVED Requirements

### Requirement: Legacy policy endpoints `/api/policy`

**Reason**: Replaced by the typed application control surface under `/api/v1/app-control/`. The legacy
endpoints exposed a singleton blocklist with two flat arrays (paths, hashes) that does not fit the
EDR-grade rule model.

**Migration**: None. The product has not shipped its first release; the legacy endpoints are deleted in
the same change.
