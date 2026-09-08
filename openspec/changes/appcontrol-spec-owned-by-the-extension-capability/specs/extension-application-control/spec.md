# Extension application control

## MODIFIED Requirements

### Requirement: Block event emission

Whenever the extension denies an AUTH_EXEC because of a `BLOCK` rule, it SHALL emit an event of kind `application_control_block`. The event SHALL carry `policy_id`, `policy_version`, `rule_id`, `rule_type`, `identifier`, `severity`, `pid`, `path`, `custom_msg` (nullable), and `custom_url` (nullable). The `identifier` SHALL be the actual value from the target tuple that caused the match (for example, the CDHash that hit a `CDHASH` rule), not the rule's own stored identifier, so an operator reading the alert sees which of the process's identities was the one that matched.

The event SHALL be emitted after the kernel has been responded to, so the JSON encode and the handoff to the upload pipeline do not run inside the AUTH_EXEC deadline.

#### Scenario: A block emits a block event whose identifier is the matched value

- **GIVEN** a `TEAMID` rule for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension denies and emits the block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `identifier` is `EQHXZ8M8AV`
- **AND** the event carries the denied process's `pid` and `path`, and the matched rule's `rule_id`, `severity`, `policy_id`, and `policy_version`

### Requirement: Snapshot persistence format is typed

The on-disk snapshot SHALL be a JSON object whose top-level fields are `policy_id`, `policy_version`, and a `rules` map keyed by `rule_type` whose values are arrays of rule records carrying at least `identifier`, `action`, `enforcement`, and optional `custom_msg`, `custom_url`, `severity`. The extension SHALL replace any pre-existing snapshot file with a fresh, typed file on first apply; the legacy `policy.json` format from the prior singleton blocklist is deleted by this change and no compatibility code SHALL be added.

On apply, each rule SHALL be routed into the map for its own `rule_type` and indexed by the identifier the precedence walk will consult for that type, so a lookup during the walk is a single map hit and no rule of one type can be reached through another type's map.

#### Scenario: A first apply replaces any prior snapshot file

- **GIVEN** an extension that has a legacy `policy.json` on disk
- **WHEN** the extension receives its first `set_application_control` command
- **THEN** the typed snapshot file is written
- **AND** the legacy file is removed

#### Scenario: Every rule type routes into its own map

- **GIVEN** a snapshot carrying one rule of each supported type
- **WHEN** the extension applies it
- **THEN** each rule is reachable in the map for its own type, keyed by its identifier
- **AND** an identifier that no rule declares is absent from every map, so the walk finds no match for it
