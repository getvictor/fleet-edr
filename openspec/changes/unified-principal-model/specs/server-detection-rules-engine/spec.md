## MODIFIED Requirements

### Requirement: Durable detection configuration surface

The system SHALL persist detection-rule configuration (per-rule mode, optional severity override, per-rule settings, and false-positive exclusions) as durable state in MySQL, edited through the authenticated admin API and UI. Detection configuration MUST NOT be sourced from boot-time environment variables. Every mutation MUST pass through the RBAC authorization chokepoint and record an audit entry naming the acting principal (a human user or a service account) by its principal id and a resolvable label. The per-row attribution column (`created_by` / `updated_by`) SHALL store the acting principal id; a service-account write MUST NOT be rejected at the persistence layer for lacking a human user id, and a system-originated write SHALL record the system principal (principal id `sys`, type `system`). Each configuration record MAY carry a host-group scope (or be global); records also support an optional expiration after which they no longer apply. A configuration change MUST become effective for subsequent evaluations without a server restart.

#### Scenario: An operator adds a false-positive exclusion without restarting

- **GIVEN** a rule that is currently producing a benign finding for a known-good process
- **WHEN** an operator adds an exclusion for that rule (by a typed match such as a parent-path glob or a signing team ID) through the detection-configuration API
- **THEN** the exclusion is persisted in MySQL with the acting principal id recorded in both the attribution column and the audit log
- **AND** subsequent batches no longer produce that finding, without a server restart

#### Scenario: A service account adds an exclusion and is attributed

- **GIVEN** an admin-roled service account holding the detection-config write permission
- **WHEN** it creates an exclusion through the detection-configuration API
- **THEN** the write succeeds without an `actor is required` rejection
- **AND** the exclusion's attribution column and the audit row both record the service account's principal id

#### Scenario: An expired exclusion stops applying

- **GIVEN** an exclusion whose expiration timestamp is in the past
- **WHEN** the engine evaluates a batch that the exclusion would otherwise suppress
- **THEN** the exclusion does not apply and the finding is produced
