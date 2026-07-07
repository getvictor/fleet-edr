## ADDED Requirements

### Requirement: A webhook-management permission gates the webhook configuration surface

The authorization model SHALL define a `webhook.manage` action that gates creating, editing, testing, and deleting webhook destinations and reading their delivery status. This action SHALL be granted to the admin role and SHALL NOT be granted to the analyst or read-only roles by default.

#### Scenario: The admin role holds the webhook-management action

- **GIVEN** an operator bound to the admin role
- **WHEN** their effective permissions are evaluated
- **THEN** they hold `webhook.manage`

#### Scenario: The analyst role does not hold the webhook-management action

- **GIVEN** an operator bound to the analyst role
- **WHEN** their effective permissions are evaluated
- **THEN** they do not hold `webhook.manage`
