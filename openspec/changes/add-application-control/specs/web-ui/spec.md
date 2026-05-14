# Web UI Specification (delta)

## ADDED Requirements

### Requirement: Application Control screen

The UI SHALL provide an Application Control section accessible from the primary navigation. The section
SHALL list every policy in the deployment with its name, rule count, assigned host-group count, and last
modified time, and SHALL allow the operator to open a policy detail view. The policy detail view SHALL show
the policy's rules in a table that can be filtered by `rule_type`, `enabled`, `source`, and free-text
search over `identifier` and `comment`, and that supports per-row enable/disable, edit, and delete actions
through the operator-session-authenticated REST surface. The view SHALL show which host group(s) the
policy is assigned to.

#### Scenario: Operator views the Default policy on a fresh deployment

- **GIVEN** a fresh deployment with no admin-authored rules
- **WHEN** the operator navigates to Application Control
- **THEN** the policies list contains exactly the seed `Default` policy with zero rules
- **AND** opening the policy detail view shows an empty rules table and the `all-hosts` group as the only
  assigned host group

### Requirement: Add-rule modal with type-aware identifier validation

The Application Control screen SHALL provide a modal for creating a rule. The modal SHALL surface a
`rule_type` selector with the values `CDHASH`, `BINARY`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`, an
`identifier` field, optional `custom_msg`, `custom_url`, `comment`, and `severity` controls, and a save
button gated on a non-empty audit `reason`. The modal SHALL validate the identifier against the format
required by the selected `rule_type` before allowing submission and SHALL surface a visible error when
validation fails.

#### Scenario: Save is blocked without a reason

- **GIVEN** the add-rule modal is open with a valid type and identifier
- **WHEN** the operator attempts to save without entering a reason
- **THEN** the modal refuses to save and surfaces a visible error explaining the reason is required

#### Scenario: An invalid identifier is rejected at the modal

- **GIVEN** the operator selects `rule_type=TEAMID` and types an identifier that is not 10 characters of
  `[A-Z0-9]`
- **WHEN** the operator attempts to submit
- **THEN** the modal refuses to submit and surfaces a visible validation error

### Requirement: Paste-many flow infers rule type by identifier shape

The Application Control screen SHALL provide a "paste many" flow that accepts a newline-delimited list of
identifiers and infers `rule_type` per line by identifier shape: 40 lowercase hex → `CDHASH`; 64 lowercase
hex → `BINARY` with a hint that the same shape is valid for `CERTIFICATE`; exactly 10 characters of
`[A-Z0-9]` → `TEAMID`; `<TeamID>:<bundle.id>` or `platform:<bundle.id>` → `SIGNINGID`; an absolute path →
`PATH`. The operator MUST confirm or override the inferred type on a per-line basis before submission.

#### Scenario: Mixed identifiers are inferred and confirmable

- **GIVEN** the operator pastes a list containing a 40-hex CDHash, a 64-hex value, a TeamID, and an
  absolute path
- **WHEN** the paste-many flow processes the input
- **THEN** each line is displayed with an inferred `rule_type`
- **AND** the 64-hex line carries a visible hint that the value could also be a `CERTIFICATE`
- **AND** the operator can override the inferred type per line before saving

## REMOVED Requirements

### Requirement: Policy editor with audit reason gate

**Reason**: Replaced by the Application Control screen, which exposes the typed rule model, host-group
scoping, and per-rule lifecycle metadata that the legacy two-textarea editor cannot represent.

**Migration**: None. The product has not shipped its first release; the legacy `PolicyEditor` is deleted
in the same change.
