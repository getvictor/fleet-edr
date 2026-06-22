# Web UI Specification

## ADDED Requirements

### Requirement: Detection configuration admin views

The web UI SHALL provide an authenticated admin surface to view and edit detection configuration: per-rule mode (alert / monitor / disabled), an optional severity override, and false-positive exclusions. The per-rule mode and severity controls MUST render uniformly for every registered rule (driven from the rule catalog), so a newly added rule appears without bespoke UI. The exclusion editor MUST let an operator create and delete global-scope exclusions with a typed match type, a value, a reason, and an optional expiration, and MUST surface the existing entries with their author and creation time. When an operator reduces a rule's alerting (sets its mode to monitor or disabled), the UI MUST capture an operator-supplied reason before the change is submitted, because that reason is recorded in the audit trail; restoring a rule to alert and severity-only edits MAY use a system-generated reason. Mutations MUST go through the authenticated admin API and are subject to the same RBAC the API enforces. Per-rule schema-driven settings beyond mode + severity, exclusion editing, and host-group-scoped configuration are deferred to a later change (they land with the editable host groups and per-rule config-schema work).

#### Scenario: An operator adds an exclusion from the UI

- **GIVEN** an authenticated operator with permission to edit detection configuration
- **WHEN** they open a rule's detection-configuration view and add an exclusion with a match type, value, and reason
- **THEN** the exclusion is created through the admin API
- **AND** it appears in the rule's exclusion list with its author and creation time

#### Scenario: Per-rule mode and severity controls render for every rule

- **GIVEN** the detection rule catalog
- **WHEN** an operator opens the detection-configuration view
- **THEN** every registered rule shows mode and severity-override controls without UI changes specific to that rule

#### Scenario: Disabling or monitoring a rule requires an operator reason

- **GIVEN** an authenticated operator with permission to edit detection configuration
- **WHEN** they set a rule's mode to disabled or monitor
- **THEN** the UI requires them to enter a reason before the change is submitted
- **AND** the change is sent to the admin API with that operator reason for the audit log
