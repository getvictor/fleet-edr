## MODIFIED Requirements

### Requirement: A service account is a non-human principal bound to a single role

The system SHALL represent a service account as a first-class principal of type `service_account` with no associated human user, carrying a stable principal id, a display name, an owning creator, exactly one bound seeded role, an expiry, and an enabled/revoked state. The expiry SHALL always be set, defaulted from the deployment-configured maximum credential lifetime and optionally shortened by the creator. The bound role MAY be any seeded role except `super_admin`, which the system MUST reject: a non-human credential carrying the unrestricted wildcard is never warranted. The `admin` role IS permitted at operator discretion, with the understanding that an admin-bound service account holds the console-management actions (`service_account.*`, `user.*`, `sso.manage`) and is therefore a full-control credential; operators SHOULD bind the least-privileged role that satisfies the automation. A verified service-account access token SHALL resolve to an actor carrying that bound role and the service account's principal id and label, evaluated by the same authorization chokepoint as a human operator.

#### Scenario: Service account resolves to a service-account principal bound to one role

- **GIVEN** an admin creates a service account bound to the `analyst` role
- **WHEN** that service account calls an API route
- **THEN** the request is authorized as an actor holding exactly the `analyst` role's actions
- **AND** the actor carries a principal of type `service_account` with the service account's principal id and label, and no human user is associated with the call

#### Scenario: A service account cannot bind to super_admin

- **WHEN** an admin attempts to create a service account bound to `super_admin`
- **THEN** the system rejects the request without creating the service account

## ADDED Requirements

### Requirement: Service-account actions are attributable to the service-account principal

The system SHALL attribute every state-changing action a service account performs to that specific service account. A service-account-initiated mutation MUST NOT be rejected at the persistence layer for lacking a human user id: any write path that records an actor SHALL accept the service-account principal id. The audit row and the per-row attribution column for such a mutation MUST record the service account's principal id (and a resolvable label), to the same standard as a user action, and MUST be queryable through the audit API alongside user attribution.

#### Scenario: A service account creates a detection exclusion and is attributed

- **GIVEN** an admin-roled service account holding the detection-config write permission
- **WHEN** it creates a detection exclusion
- **THEN** the write succeeds without an `actor is required` rejection
- **AND** the exclusion's attribution column and the audit row both record the service account's principal id

#### Scenario: A service account updates SSO configuration and is attributed

- **GIVEN** a service account holding `sso.manage`
- **WHEN** it updates the OIDC configuration
- **THEN** the write succeeds and records the service account's principal id as the updater, never a null or zero actor

#### Scenario: A service-account-reachable write never fails on actor shape

- **GIVEN** any mutating route on the authenticated mux exercised with a service-account actor of sufficient role
- **WHEN** the request is processed
- **THEN** it either succeeds or is denied for a deliberate authorization reason, never rejected because the actor carries no human user id
