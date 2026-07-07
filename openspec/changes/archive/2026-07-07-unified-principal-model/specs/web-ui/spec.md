## MODIFIED Requirements

### Requirement: Detection configuration admin views

The web UI SHALL provide an authenticated admin surface to view and edit detection configuration: per-rule mode (alert / disabled), an optional severity override, and false-positive exclusions. Monitor is NOT an operator-selectable mode; the detection engine still honors a legacy `monitor` value persisted on a rule setting, so the UI MUST display such a row (and let the operator migrate it to alert or disabled) but MUST NOT offer monitor as a new choice. The per-rule mode and severity controls MUST render uniformly for every registered rule (driven from the rule catalog), so a newly added rule appears without bespoke UI, and the table MUST show each rule's declared (default) severity alongside the optional override. The exclusion editor MUST let an operator create and delete global-scope exclusions with a typed match type, a value, a reason, and an optional expiration, and MUST surface the existing entries with their creation time and their author resolved to a display label: a human user's email, a service account's name, or "system" for the system principal, falling back to the raw principal identifier when the principal cannot be resolved. When an operator disables a rule, the UI MUST capture an operator-supplied reason before the change is submitted, because that reason is recorded in the audit trail; restoring a rule to alert and severity-only edits MAY use a system-generated reason. Mutations MUST go through the authenticated admin API and are subject to the same RBAC the API enforces. Per-rule schema-driven settings beyond mode + severity, exclusion editing, and host-group-scoped configuration are deferred to a later change (they land with the editable host groups and per-rule config-schema work).

#### Scenario: An operator adds an exclusion from the UI

- **GIVEN** an authenticated operator with detection-config write access
- **WHEN** they add an exclusion with a match type, value, and reason
- **THEN** the exclusion is created through the admin API
- **AND** it appears in the exclusion list with its creation time and its author shown as a resolved label (a user's email or a service account's name)

#### Scenario: Per-rule mode and severity controls render for every rule

- **GIVEN** the rule catalog registers a set of rules
- **WHEN** an operator opens the detection-configuration admin view
- **THEN** every registered rule shows mode and severity-override controls without UI changes specific to that rule
- **AND** each rule's declared default severity is shown alongside its optional override

#### Scenario: Disabling a rule requires an operator reason

- **GIVEN** an authenticated operator with detection-config write access
- **WHEN** they set a rule's mode to disabled
- **THEN** the UI captures an operator-supplied reason before submitting the change
- **AND** restoring the rule to alert or editing only its severity override does not require an operator-supplied reason (a system-generated reason is recorded instead)

#### Scenario: Monitor is not an operator-selectable mode

- **GIVEN** an authenticated operator viewing the rule-modes table
- **WHEN** they open a rule's mode control
- **THEN** a rule with no persisted monitor setting offers only alert and disabled
- **AND** a rule with a legacy persisted monitor value still displays monitor so the operator can migrate it to alert or disabled

#### Scenario: Exclusion author is shown as a resolved email

- **GIVEN** an exclusion whose author is a known user
- **WHEN** the operator views the exclusions list
- **THEN** the Created by column shows that user's email
- **AND** an exclusion whose author cannot be resolved falls back to the raw principal identifier

#### Scenario: Exclusion author shows a service account name

- **GIVEN** an exclusion whose author is a service account
- **WHEN** the operator views the exclusions list
- **THEN** the Created by column shows that service account's name rather than the raw principal identifier
