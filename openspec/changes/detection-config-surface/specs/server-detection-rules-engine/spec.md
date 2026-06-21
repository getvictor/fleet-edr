# Server Detection Rules Engine Specification

## MODIFIED Requirements

### Requirement: Operator toggling of individual rules

The system SHALL allow an operator to set an individual rule's mode to one of `alert`, `monitor`, or `disabled` through the durable detection-configuration surface (persisted in MySQL, edited via the admin API/UI), NOT through boot-time environment configuration. The mode MAY be set at global scope or scoped to a host group, and resolves per host most-specific-wins (a host-group setting overrides the global setting for hosts in that group). A rule that resolves to `disabled` for a host MUST NOT produce alerts for that host. A rule that resolves to `monitor` for a host MUST evaluate but MUST NOT persist an alert, emitting an observability signal instead so the would-be detection is visible without alerting. A rule that resolves to `alert` produces alerts as normal. A mode change MUST take effect without a server restart. A rule whose global mode is `disabled` MUST remain visible in the rule catalog surface (`GET /api/rules`) with its mode indicated rather than being removed from the catalog.

#### Scenario: An operator disables a noisy rule for their environment

- **GIVEN** a running engine and an operator who sets a rule's global mode to `disabled` through the detection-configuration API
- **WHEN** a batch arrives that would otherwise satisfy that rule
- **THEN** no alerts are produced for that rule
- **AND** the remaining rules continue to evaluate normally
- **AND** the disabled rule is still listed by `GET /api/rules`, marked disabled
- **AND** the change took effect without a server restart

#### Scenario: A rule set to monitor evaluates without alerting

- **GIVEN** a rule whose global mode is set to `monitor`
- **WHEN** a batch arrives that satisfies the rule for a host
- **THEN** no alert is persisted for that rule and host
- **AND** an observability signal records that the rule matched

#### Scenario: An operator re-enables a previously disabled rule

- **GIVEN** a rule whose global mode was previously set to `disabled`
- **WHEN** the operator sets its mode back to `alert` through the API
- **THEN** subsequent batches that satisfy the rule produce alerts again without a server restart

## ADDED Requirements

### Requirement: Durable detection configuration surface

The system SHALL persist detection-rule configuration (per-rule enable state, optional severity override, per-rule settings, and false-positive exclusions) as durable state in MySQL, edited through the authenticated admin API and UI. Detection configuration MUST NOT be sourced from boot-time environment variables. Every mutation MUST pass through the RBAC authorization chokepoint and record an audit entry naming the actor. Each configuration record MAY carry a host-group scope (or be global); records also support an optional expiration after which they no longer apply. A configuration change MUST become effective for subsequent evaluations without a server restart.

#### Scenario: An operator adds a false-positive exclusion without restarting

- **GIVEN** a rule that is currently producing a benign finding for a known-good process
- **WHEN** an operator adds an exclusion for that rule (by a typed match such as a parent-path glob or a signing team ID) through the detection-configuration API
- **THEN** the exclusion is persisted in MySQL with the actor recorded in the audit log
- **AND** subsequent batches no longer produce that finding, without a server restart

#### Scenario: An expired exclusion stops applying

- **GIVEN** an exclusion whose expiration timestamp is in the past
- **WHEN** the engine evaluates a batch that the exclusion would otherwise suppress
- **THEN** the exclusion does not apply and the finding is produced

### Requirement: Per-host resolution of exclusions and rule settings

The system SHALL resolve detection exclusions and per-rule settings per host at evaluation time. Before a rule produces a finding for a given host, the engine MUST suppress that finding when an exclusion of the relevant match type applies to the host, where an exclusion applies if its scope is global OR a host group the host belongs to, and it has not expired. An exclusion scoped to a host group MUST NOT suppress findings for hosts outside that group. Per-rule mode and severity override MUST resolve most-specific-wins (host-group scope overrides global scope) for the finding's host.

#### Scenario: A host-group-scoped exclusion does not affect other hosts

- **GIVEN** an exclusion for a rule scoped to a specific host group
- **WHEN** the rule's pattern is satisfied on a host that is NOT a member of that group
- **THEN** the finding is still produced for that host

#### Scenario: A global exclusion suppresses the finding on every host

- **GIVEN** an exclusion for a rule at global scope
- **WHEN** the rule's pattern is satisfied on any host
- **THEN** the finding is suppressed for that host
