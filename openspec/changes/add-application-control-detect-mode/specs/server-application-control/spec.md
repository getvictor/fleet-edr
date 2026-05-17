# Server Application Control Specification (delta)

## ADDED Requirements

### Requirement: Per-rule enforcement DETECT honors a log-only contract

The system SHALL honor each rule's `enforcement` value when fanning out the rule to extensions and
when persisting block-decision events back from those extensions. Rules with `enforcement='PROTECT'`
SHALL produce `application_control_block` events on match and SHALL be authoritative blocks at the
extension. Rules with `enforcement='DETECT'` SHALL produce `application_control_would_block` events
on match and SHALL be allow-but-log at the extension. The server SHALL ingest both event kinds
through the same `POST /api/events` channel that carries every other agent event, with the same
host-token-authenticated authenticity binding.

#### Scenario: A would-block event is accepted and authenticity-bound

- **GIVEN** an authenticated agent posts an `application_control_would_block` event whose envelope
  `host_id` matches the authenticated host
- **WHEN** the server ingests the event
- **THEN** the server responds with HTTP 200
- **AND** the event is stamped with the authenticated `host_id`

#### Scenario: A would-block event for a forged host_id is rejected

- **GIVEN** an authenticated agent posts an `application_control_would_block` event whose envelope
  `host_id` does not match the authenticated host
- **WHEN** the server validates the request
- **THEN** the server responds with HTTP 4xx
- **AND** the event is not persisted

### Requirement: Default Detect on rule creation

The system SHALL default new `app_control_rules` to `enforcement='DETECT'` when the operator does
not supply an explicit value. The PATCH endpoint SHALL accept either `PROTECT` or `DETECT` on
update. The default is the schema-column default; existing rules retain their stored value across
the deploy that activates this change.

#### Scenario: Creating a rule without explicit enforcement lands in Detect

- **GIVEN** an authenticated operator posts a rule create request with no `enforcement` field
- **WHEN** the server validates and persists the rule
- **THEN** the persisted rule has `enforcement='DETECT'`

#### Scenario: An existing PROTECT rule is unaffected by the default flip

- **GIVEN** a rule that was created before this change with `enforcement='PROTECT'`
- **WHEN** the server boots with the new schema
- **THEN** the rule retains `enforcement='PROTECT'`

### Requirement: PATCH endpoint for rule enforcement change

The system SHALL accept a partial-body `PATCH /api/v1/app-control/rules/{id}` request containing
one or more of `enforcement`, `severity`, `custom_msg`, `custom_url`, `comment`, `enabled`, with a
required non-empty `reason`. The system SHALL emit exactly one audit event per PATCH carrying the
operator's identity, the supplied reason, the rule and policy identifiers, and a structured diff
of the change. The system SHALL fan out the updated snapshot to every host the rule's policy is
assigned to with the updated `enforcement` value.

#### Scenario: Promoting a Detect rule to Protect

- **GIVEN** an existing rule with `enforcement='DETECT'`
- **WHEN** the operator PATCHes the rule with `{enforcement: "PROTECT", reason: "promote after
  watching alerts for 7 days"}`
- **THEN** the rule's persisted `enforcement` is `'PROTECT'`
- **AND** an audit event records the operator, the reason, and a diff showing
  `enforcement: DETECT → PROTECT`
- **AND** a `set_application_control` fan-out command is enqueued for every host assigned to the
  rule's policy

#### Scenario: PATCH without a reason is rejected

- **GIVEN** an existing rule
- **WHEN** the operator PATCHes the rule with `{enforcement: "PROTECT"}` and no `reason` field
- **THEN** the server responds with a typed error indicating the reason is required
- **AND** the rule is not mutated
- **AND** no audit event is emitted

#### Scenario: PATCH with an invalid enforcement value is rejected

- **GIVEN** an existing rule
- **WHEN** the operator PATCHes the rule with `{enforcement: "MAYBE", reason: "experiment"}`
- **THEN** the server responds with a typed error indicating the enforcement value is invalid
- **AND** the rule is not mutated

## MODIFIED Requirements

### Requirement: Rule identifies one binary, signing identity, or path

The system SHALL represent every rule as a row owned by exactly one policy and carrying: a
`rule_type` from the set `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`; an `identifier`
string whose format is determined by `rule_type`; an `action` constrained in this phase to `BLOCK`;
an `enforcement` from `{PROTECT, DETECT}` defaulting to `DETECT`; an `enabled` flag; a `severity`
from `{low, medium, high, critical}` defaulting to `medium`; a `source` from
`{admin, imported, intel}` defaulting to `admin`; an optional `source_ref`; an optional
`custom_msg`; an optional `custom_url`; an optional `comment`; an optional `expires_at`; and
timestamps and actor identity. The triple `(policy_id, rule_type, identifier)` SHALL be unique.

The change from the prior requirement is the `enforcement` default: it flips from `'PROTECT'` to
`'DETECT'` so that new rules ship safely. Operators promote to Protect via PATCH once confident in
the rule's behavior.

#### Scenario: Two rules in the same policy can target the same identifier under different types

- **GIVEN** a policy that already contains a `BINARY` rule for hash `H`
- **WHEN** the operator adds a `PATH` rule for `/usr/local/bin/H`
- **THEN** the system creates the new rule successfully because the unique key includes `rule_type`

#### Scenario: Duplicating the same `(rule_type, identifier)` is rejected

- **GIVEN** a policy that already contains a `TEAMID` rule for `EQHXZ8M8AV`
- **WHEN** the operator attempts to create a second `TEAMID` rule with the same identifier in the
  same policy
- **THEN** the system rejects the request with a typed error indicating the rule already exists

### Requirement: Application control block event contract

The system SHALL accept ingest events of kind `application_control_block` and
`application_control_would_block` from agents through the same host-token-authenticated
`POST /api/events` channel that carries every other agent event. The system MUST bind every
accepted event to the `host_id` resolved by the existing host-token middleware and MUST reject
events whose envelope `host_id` does not match the authenticated host. Each event MUST carry
`policy_id`, `policy_version`, `rule_id`, `rule_type`, `rule_identifier`, `matched_identifier`,
`severity`, `process`, and `ancestry`. The event MAY carry optional `custom_msg` and `custom_url`.
The system SHALL accept events whose `policy_id` or `rule_id` does not correspond to a known rule
(so an in-flight decision is not lost when a rule is deleted after the AUTH path fired) and SHALL
log a server-side warning for operator visibility on the unknown-rule path.

The change from the prior requirement adds `application_control_would_block` to the set of
recognised event kinds with identical handling. The two differ only in the alert subtype the
detection-rules engine stamps on the resulting alert row.

#### Scenario: A would-block event for an unknown rule is accepted but warned

- **GIVEN** an agent posts an `application_control_would_block` event whose `rule_id` does not
  exist
- **WHEN** the server ingests the event
- **THEN** the server responds with HTTP 200
- **AND** the server emits a structured warning identifying the unknown rule id

#### Scenario: A block event for a now-deleted rule is accepted

- **GIVEN** a rule that existed when the agent denied the exec but was deleted before the event
  reached the server
- **WHEN** the agent posts the `application_control_block` event
- **THEN** the server accepts and persists the event so the historical decision is not lost
