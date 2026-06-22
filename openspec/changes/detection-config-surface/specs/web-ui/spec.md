# Web UI Specification

## ADDED Requirements

### Requirement: Detection configuration admin views

The web UI SHALL provide an authenticated admin surface to view and edit detection configuration: per-rule mode (alert / monitor / disabled), optional severity override, per-rule settings, and false-positive exclusions. The per-rule settings form MUST be rendered generically from each rule's declared configuration schema so a newly added rule's settings appear without bespoke UI. The exclusion editor MUST let an operator create, edit, and delete exclusions with a typed match type, a value, a reason, an optional expiration, and a scope (global or a host group), and MUST surface the existing entries with their author and creation time. Mutations MUST go through the authenticated admin API and are subject to the same RBAC the API enforces.

#### Scenario: An operator adds an exclusion from the UI

- **GIVEN** an authenticated operator with permission to edit detection configuration
- **WHEN** they open a rule's detection-configuration view and add an exclusion with a match type, value, and reason
- **THEN** the exclusion is created through the admin API
- **AND** it appears in the rule's exclusion list with its author and creation time

#### Scenario: A rule's settings render from its declared schema

- **GIVEN** a rule that declares configurable settings in its schema
- **WHEN** an operator opens that rule's detection-configuration view
- **THEN** the settings form renders the declared fields without UI changes specific to that rule
