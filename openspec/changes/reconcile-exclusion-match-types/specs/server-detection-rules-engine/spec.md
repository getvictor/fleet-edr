## MODIFIED Requirements

### Requirement: Durable detection configuration surface

The system SHALL persist detection-rule configuration (per-rule mode, optional severity override, per-rule settings, and false-positive exclusions) as durable state in MySQL, edited through the authenticated admin API and UI. Detection configuration MUST NOT be sourced from boot-time environment variables. Every mutation MUST pass through the RBAC authorization chokepoint and record an audit entry naming the actor. Each configuration record MAY carry a host-group scope (or be global); records also support an optional expiration after which they no longer apply. A configuration change MUST become effective for subsequent evaluations without a server restart.

Each registered rule SHALL declare the set of exclusion match types it consults at evaluation time, and the rule catalog surface (`GET /api/rules`) SHALL expose that set for every rule so operator tooling can offer only the match types a rule actually reads. Creating an exclusion SHALL be rejected when its `rule_id` does not name a registered rule, and when its `match_type` is not one the named rule consults; the rejection is a client error that names the supported match types. This prevents an operator from storing an exclusion whose `(rule_id, match_type)` pair no rule reads, which would otherwise be accepted and displayed as active while suppressing nothing.

#### Scenario: An operator adds a false-positive exclusion without restarting

- **GIVEN** a rule that is currently producing a benign finding for a known-good process
- **WHEN** an operator adds an exclusion for that rule (by a typed match such as a parent-path glob or a signing team ID) through the detection-configuration API
- **THEN** the exclusion is persisted in MySQL with the actor recorded in the audit log
- **AND** subsequent batches no longer produce that finding, without a server restart

#### Scenario: An expired exclusion stops applying

- **GIVEN** an exclusion whose expiration timestamp is in the past
- **WHEN** the engine evaluates a batch that the exclusion would otherwise suppress
- **THEN** the exclusion does not apply and the finding is produced

#### Scenario: The rule catalog exposes per-rule supported exclusion match types

- **GIVEN** the registered rule catalog
- **WHEN** a client reads `GET /api/rules`
- **THEN** each rule carries the set of exclusion match types it consults, as an array (empty for a rule that consults no exclusions)

#### Scenario: Creating an exclusion for a match type the rule does not consult is rejected

- **GIVEN** a rule that consults a fixed set of exclusion match types
- **WHEN** an operator attempts to create an exclusion for that rule with a match type outside the rule's supported set
- **THEN** the request is rejected as a client error whose message names the rule's supported match types
- **AND** no exclusion is persisted

#### Scenario: Creating an exclusion for an unknown rule is rejected

- **GIVEN** a `rule_id` that names no registered rule (including the empty string)
- **WHEN** an operator attempts to create an exclusion for it
- **THEN** the request is rejected as a client error and no exclusion is persisted

## ADDED Requirements

### Requirement: Signature-based parent exclusions

The `suspicious_exec` rule SHALL suppress a finding when the chain's non-shell parent process matches an operator exclusion by its code-signing identity, in addition to the existing parent-path-glob match. The consulted signature dimensions are the parent's Apple Developer team ID (`team_id`), its code-signing identifier (`signing_id`), and its code-directory hash (`cdhash`), read from the parent process's already-persisted code-signing record; no agent or event-wire change is required. A finding with no resolved non-shell parent, or a parent that carries no signing identity, MUST NOT be suppressed by a signature exclusion, so an unsigned binary at a benign-looking path is not silently allowed. This lets an operator exclude a code-signed developer tool by its non-spoofable signing identity instead of a path glob that an attacker who can write to a world-writable directory could land inside.

#### Scenario: A signed parent is suppressed by its team ID

- **GIVEN** a `suspicious_exec` chain whose non-shell parent is a code-signed binary with team ID `Q6L2SF6YDW`
- **AND** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the parent's signing team ID matches the exclusion
- **AND** the same holds for a `signing_id` exclusion matching the parent's signing identifier and a `cdhash` exclusion matching the parent's code-directory hash

#### Scenario: An unsigned lookalike parent is not suppressed

- **GIVEN** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **AND** a `suspicious_exec` chain whose non-shell parent is an unsigned binary at a path resembling the benign tool (for example `/tmp/claude/versions/1.0/claude`)
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the finding is produced, because the unsigned parent carries no team ID for the signature exclusion to match
