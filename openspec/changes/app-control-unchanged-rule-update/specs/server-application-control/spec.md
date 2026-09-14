## ADDED Requirements

### Requirement: An unchanged rule update is not a mutation

A `PATCH /api/v1/app-control/rules/{id}` for an existing rule whose supplied fields all equal the rule's current values SHALL succeed and return the rule. Because nothing changed, it SHALL NOT increment the policy version, enqueue `set_application_control` commands, or emit an audit event. A `PATCH` that changes at least one field SHALL remain a mutation, whatever the other fields it supplies. A `PATCH` for a rule that does not exist, including one deleted while the request was in flight, SHALL fail with `application_control.rule_not_found`.

#### Scenario: An unchanged update returns the rule

- **GIVEN** a rule with enforcement `PROTECT` and severity `medium`, in a policy at version `N`
- **WHEN** an operator sends a `PATCH` setting enforcement to `PROTECT` and severity to `medium`
- **THEN** the response is 200 with the rule
- **AND** the policy is still at version `N`, no `set_application_control` command is enqueued, and no audit event is recorded

#### Scenario: Changing one field is a mutation

- **GIVEN** a rule with enforcement `PROTECT` and severity `medium`
- **WHEN** an operator sends a `PATCH` setting enforcement to `PROTECT` and severity to `high`
- **THEN** the rule's severity is `high`, the policy version increments, the snapshot fans out, and an audit event is recorded
