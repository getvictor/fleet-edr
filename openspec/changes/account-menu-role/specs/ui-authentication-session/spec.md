## ADDED Requirements

### Requirement: The session probe names the operator's roles

`GET /api/session` SHALL return, alongside the effective permissions, the identifiers of the roles the operator holds deployment-wide, sorted and without duplicates, as an array that is present and possibly empty. They SHALL be the same role bindings the permissions are computed from.

#### Scenario: The probe returns the roles the session carries

- **GIVEN** an operator whose only role binding is `auditor`, deployment-wide
- **WHEN** their session is probed
- **THEN** the response names the role `auditor`
