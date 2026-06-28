## ADDED Requirements

### Requirement: The authenticated actor carries a typed principal

The system SHALL resolve every authenticated request to an actor that carries a typed principal: a stable principal id, a principal type from the set `{user, service_account, system}`, and a display label. The principal MUST survive authentication for every actor kind, so a service-account request carries the service account's principal id and label rather than an empty actor. The chokepoint and every privileged handler SHALL identify the actor by its principal id, never by assuming a human user id is present. The principal id is the single value used for audit attribution and for per-row attribution columns. This requirement does not change the role evaluation the chokepoint performs: a service account continues to evaluate against its single bound role.

#### Scenario: A user request carries a user principal

- **GIVEN** an authenticated human operator session
- **WHEN** middleware builds the actor
- **THEN** the actor carries a principal of type `user` with a principal id and a display label derived from the user record

#### Scenario: A service-account request carries a service-account principal

- **GIVEN** a valid service-account access token
- **WHEN** the authenticator resolves it to an actor
- **THEN** the actor carries a principal of type `service_account` with the service account's principal id and label, and no human user id

#### Scenario: Handlers identify the actor by principal id

- **GIVEN** a privileged handler that attributes a mutation
- **WHEN** it records who acted
- **THEN** it uses the actor's principal id, which is non-empty for both user and service-account actors
