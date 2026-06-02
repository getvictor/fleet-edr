# Extension Application Control Specification (delta)

## ADDED Requirements

### Requirement: Detect-mode allows the exec and emits a would-block event

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=DETECT`, the extension SHALL
allow the AUTH_EXEC request to proceed and SHALL emit an event of kind `application_control_would_block`
carrying the same payload fields as `application_control_block`. The extension SHALL NOT fire the host-app
notification modal on the Detect path; the modal is reserved for actual blocks so the operator's desktop
signal matches the operational reality.

#### Scenario: A DETECT rule allows the exec and emits a would-block event

- **GIVEN** the precedence walk for an exec returns a rule with `action=BLOCK`,
  `enforcement=DETECT`
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** an `application_control_would_block` event is emitted carrying the rule and matched
  identifier
- **AND** no host-app notification modal is presented

#### Scenario: A DETECT rule's matched_identifier matches the rule type

- **GIVEN** a `TEAMID` rule with `enforcement=DETECT` matches an exec by team id `EQHXZ8M8AV`
- **WHEN** the extension emits the would-block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `matched_identifier` is `EQHXZ8M8AV`

### Requirement: Every AUTH_EXEC decision emits a regular exec event

The extension SHALL emit a regular exec event for every AUTH_EXEC the kernel raises, regardless of
the decision the precedence walker returns. The exec event SHALL carry the standard payload fields
plus an optional `decision` field whose value is `'blocked'` when the AUTH path denied because of a
PROTECT rule, `'would_block'` when the AUTH path allowed-but-flagged because of a DETECT rule, and
absent in every other case. The regular exec event ensures the server-side graph builder
materializes a process row for the attempted-but-blocked exec and that catalog detection rules
observe the attempt the same way they observe ordinary execs.

#### Scenario: A PROTECT block emits both the block event and the regular exec event

- **GIVEN** a PROTECT rule matches an exec
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is deny
- **AND** an `application_control_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='blocked'`

#### Scenario: A DETECT match emits both the would-block event and the regular exec event

- **GIVEN** a DETECT rule matches an exec
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** an `application_control_would_block` event is emitted
- **AND** a regular `exec` event is emitted with `decision='would_block'`

#### Scenario: An exec with no matching rule emits the regular exec event without the decision field

- **GIVEN** the precedence walk for an exec returns no match
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** a regular `exec` event is emitted with no `decision` field

## MODIFIED Requirements

### Requirement: AUTH_EXEC denial on BLOCK match

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=PROTECT`, the extension SHALL
deny the AUTH_EXEC request so the new image does not run and SHALL emit an `application_control_block` event
plus a regular exec event with `decision='blocked'`. When the walk returns a rule whose `action=BLOCK` and
`enforcement=DETECT`, the extension SHALL allow the AUTH_EXEC request to proceed and SHALL emit an
`application_control_would_block` event plus a regular exec event with `decision='would_block'`. When the walk
returns no match, the extension SHALL allow the AUTH_EXEC request to proceed and SHALL emit a regular exec
event with no `decision` field. The decision SHALL be reached within the AUTH_EXEC deadline; the extension MUST
NOT block on signing-info fetches to reach a decision.

The change from the prior requirement is the explicit handling of the `enforcement=DETECT` branch
(previously the requirement only covered `enforcement=PROTECT` and treated other values as
unsupported) and the explicit requirement to emit the regular exec event on every decision.

#### Scenario: A PROTECT rule denies the exec

- **GIVEN** the precedence walk for an exec returns a `BLOCK` / `PROTECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is a deny
- **AND** the new image does not run
- **AND** an `application_control_block` event and a regular exec event are emitted

#### Scenario: A DETECT rule allows the exec

- **GIVEN** the precedence walk for an exec returns a `BLOCK` / `DETECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** the new image runs
- **AND** an `application_control_would_block` event and a regular exec event are emitted

#### Scenario: No matching rule allows the exec

- **GIVEN** the precedence walk for an exec returns no match
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** a regular exec event is emitted with no `decision` field

### Requirement: Block event emission

Whenever the extension takes a non-trivial decision on an AUTH_EXEC because of a `BLOCK` rule, it SHALL emit
one of two events. For `enforcement=PROTECT` matches the kind is `application_control_block` and the AUTH
response is deny. For `enforcement=DETECT` matches the kind is `application_control_would_block` and the AUTH
response is allow. Both events SHALL carry identical fields: `policy_id`, `policy_version`, `rule_id`,
`rule_type`, `rule_identifier`, `matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url`
(nullable), `process`, and `ancestry`. The `matched_identifier` SHALL be the actual value from the target
tuple that caused the match (for example, the CDHash that hit a `CDHASH` rule).

The change from the prior requirement is the dual event kind (PROTECT → block, DETECT →
would_block) with identical payload shape.

#### Scenario: A block emits a block event whose matched_identifier matches the rule type

- **GIVEN** a `TEAMID` rule with `enforcement=PROTECT` for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension denies and emits the block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `matched_identifier` is `EQHXZ8M8AV`

#### Scenario: A would-block emits a would-block event with the same shape

- **GIVEN** a `TEAMID` rule with `enforcement=DETECT` for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension allows and emits the would-block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `matched_identifier` is `EQHXZ8M8AV`
