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

## MODIFIED Requirements

### Requirement: Rule lifecycle audit events

The system SHALL emit an audit event for every create, update, or delete of a policy or a rule. A rule update that changes nothing is not an update for this purpose and SHALL NOT emit one (see "An unchanged rule update is not a mutation"). The event SHALL include the acting principal (its principal id and a resolvable label, for a human user or a service account alike), the reason supplied with the request, the policy and (for rule events) rule identifier, and a structured diff of the change. The per-row attribution columns (`created_by` / `updated_by`) SHALL store the acting principal id, not a human-only identifier, and a system-originated write SHALL record the system principal (principal id `sys`, type `system`) rather than a free-form literal such as `"system"`. A `bulkUpsert` SHALL emit exactly one audit event covering the logical operation rather than one event per touched rule. A service-account write MUST NOT be rejected at the persistence layer for lacking a human user id.

The change from the prior requirement is the exception for a rule update that changes nothing, which previously fell under "every update".

#### Scenario: Creating a rule records the acting principal

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully creates a rule
- **THEN** the audit log contains a new event with the acting principal id and label, the supplied reason, the policy and rule identifiers, and a diff describing the created rule
- **AND** the rule's `created_by` column stores that principal id

#### Scenario: A service account creates a rule and is attributed

- **GIVEN** an admin-roled service account
- **WHEN** it successfully creates a rule
- **THEN** the write succeeds without an `actor is required` rejection
- **AND** the audit event and the `created_by` column record the service account's principal id

#### Scenario: Bulk upsert emits a single audit event

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully bulk-upserts twenty rules
- **THEN** the audit log gains exactly one event recording the logical operation, the acting principal, and the count of touched rules
