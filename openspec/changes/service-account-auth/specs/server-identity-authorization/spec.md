## ADDED Requirements

### Requirement: Service-account management actions are registered and admin-scoped

The system SHALL register the actions `service_account.read`, `service_account.create`, `service_account.rotate`, and `service_account.revoke` in the authorization action enumeration, mirrored in the policy bundle so the build-time parity check holds. These actions SHALL be granted to the seeded `admin` role; `super_admin` covers them via its wildcard. The service-account management endpoints SHALL funnel through the chokepoint on these actions like every other privileged action.

#### Scenario: Admin holds the service-account actions

- **GIVEN** an operator with the seeded `admin` role
- **WHEN** the chokepoint evaluates a `service_account.create` request
- **THEN** the decision is allow

#### Scenario: A role without the grant is denied

- **GIVEN** an operator with only the `analyst` role
- **WHEN** the chokepoint evaluates a `service_account.create` request
- **THEN** the decision is deny with the no-matching-rule reason

### Requirement: A service-account actor is evaluated by the chokepoint but is never session-fresh

The system SHALL resolve a verified service-account access token to an actor carrying the service account's bound role, evaluated by the same authorization chokepoint as a human actor. A service-account actor SHALL never be considered session-fresh. The reauth freshness gate, which protects destructive actions for interactive human sessions, SHALL NOT apply to a service-account actor; whether a service account may perform a destructive action SHALL be determined solely by whether its bound role grants that action.

#### Scenario: Service-account actor authorized purely by role

- **GIVEN** a service account whose bound role grants `host.isolate`
- **WHEN** it calls the host-isolate endpoint with a valid access token
- **THEN** the chokepoint allows the action without requiring session freshness

#### Scenario: Role without the action is denied regardless of token validity

- **GIVEN** a service account whose bound role does not grant `host.isolate`
- **WHEN** it calls the host-isolate endpoint with a valid access token
- **THEN** the chokepoint denies the action
