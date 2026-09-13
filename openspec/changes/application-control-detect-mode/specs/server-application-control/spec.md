# Server application control delta

## MODIFIED Requirements

### Requirement: Rule identifies one binary, signing identity, or path

The system SHALL represent every rule as a row owned by exactly one policy and carrying: a `rule_type` from the set `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`; an `identifier` string whose format is determined by `rule_type`; an `action` constrained in this phase to `BLOCK`; an `enforcement` from `{PROTECT, DETECT}` defaulting to `PROTECT` when the request that creates the rule does not name one; an `enabled` flag; a `severity` from `{low, medium, high, critical}` defaulting to `medium`; a `source` from `{admin, imported, intel}` defaulting to `admin`; an optional `source_ref`; an optional `custom_msg`; an optional `custom_url`; an optional `comment`; an optional `expires_at`; and timestamps and actor identity. The triple `(policy_id, rule_type, identifier)` SHALL be unique.

A `PROTECT` rule denies an exec it matches. A `DETECT` rule lets the exec run, and the host reports the match so it is kept as a monitor record; a `DETECT` rule never changes the verdict another rule reaches. The change from the prior requirement is that `DETECT` has a meaning: it was accepted and stored, and no rule could be created with it.

#### Scenario: Two rules in the same policy can target the same identifier under different types

- **GIVEN** a policy that already contains a `BINARY` rule for hash `H`
- **WHEN** the operator adds a `PATH` rule for `/usr/local/bin/H`
- **THEN** the system creates the new rule successfully because the unique key includes `rule_type`

#### Scenario: Duplicating the same `(rule_type, identifier)` is rejected

- **GIVEN** a policy that already contains a `TEAMID` rule for `EQHXZ8M8AV`
- **WHEN** the operator attempts to create a second `TEAMID` rule with the same identifier in the same policy
- **THEN** the system rejects the request with a typed error indicating the rule already exists

## ADDED Requirements

### Requirement: Rule enforcement is chosen on create and changed on update

The rule-create endpoint SHALL accept an optional `enforcement` of `PROTECT` or `DETECT`, and SHALL store `PROTECT` when the request omits it, so a caller that predates Detect mode keeps getting rules that block. The rule-update endpoint SHALL accept `enforcement` as a mutable field, which is how an operator promotes a `DETECT` rule to `PROTECT` or moves it back. Either endpoint SHALL reject any other value with a validation error and SHALL change nothing. A change of enforcement SHALL bump the policy version and push the new snapshot to the policy's hosts like any other rule mutation, and the create and update audit events SHALL record the rule's enforcement.

#### Scenario: A rule created in DETECT reaches hosts in DETECT

- **GIVEN** an operator creating a rule with `enforcement=DETECT`
- **WHEN** the request succeeds
- **THEN** the stored rule's enforcement is `DETECT`
- **AND** the snapshot pushed to the policy's hosts carries the rule with `enforcement=DETECT`
- **AND** the audit event records `DETECT`

#### Scenario: A rule created without an enforcement blocks

- **GIVEN** an operator creating a rule without an `enforcement` field
- **WHEN** the request succeeds
- **THEN** the stored rule's enforcement is `PROTECT`

#### Scenario: Promoting a rule pushes and audits the new enforcement

- **GIVEN** a rule whose enforcement is `DETECT`
- **WHEN** an operator updates it with `enforcement=PROTECT` and a reason
- **THEN** the stored rule's enforcement is `PROTECT` and the policy version is bumped
- **AND** the snapshot pushed to the policy's hosts carries `enforcement=PROTECT`
- **AND** the update audit event records `PROTECT` and the reason

#### Scenario: An unknown enforcement is rejected

- **GIVEN** an operator creating or updating a rule with an `enforcement` other than `PROTECT` or `DETECT`
- **WHEN** the request is handled
- **THEN** the server responds with HTTP 400
- **AND** no rule is created or changed
