# Web UI Specification

## REMOVED Requirements

### Requirement: Policy editor with audit reason gate

**Reason**: Replaced by the Application Control screen, which exposes the typed rule model and per-rule lifecycle metadata the legacy two-textarea editor could not represent. `2026-06-02-add-application-control` retired this requirement and deleted the legacy `PolicyEditor` component in the same change; the archive applied the deletion to the code but not the retirement to the spec, so the canonical tree has gone on describing an editor that stages "paths and SHA-256 hashes" and has not existed since. No such component remains in `ui/src`.

**Migration**: None. The component was deleted before the first release.

## ADDED Requirements

### Requirement: Application control screen lists policies and their rules

The UI SHALL provide an Application Control section reachable from the primary navigation. The section SHALL list every policy in the deployment with its name, its rule count, its version, the number of host groups it is assigned to, and when it was last modified, and SHALL let the operator open a policy detail view.

The policy detail view SHALL show the policy's rules in a table carrying each rule's type, identifier, severity, custom message, and last-modified time, and SHALL offer per-row enable, disable, edit and delete actions through the operator-session-authenticated REST surface. The table SHALL be filterable by rule type, by enabled state, and by source, and by a free-text search matched against the identifier OR the comment. Each filter dimension SHALL be independent, so an unset dimension admits every rule.

#### Scenario: A fresh deployment shows the seeded default policy

- **GIVEN** a deployment with no operator-authored rules
- **WHEN** the operator opens Application Control
- **THEN** the policies list shows the seeded `Default` policy with a rule count of zero
- **AND** the row reports how many host groups the policy is assigned to

#### Scenario: The rules table filters independently on each dimension

- **GIVEN** a policy detail view listing rules of more than one type, state and source
- **WHEN** the operator sets one filter dimension and leaves the others unset
- **THEN** only rules matching that dimension are listed, and the unset dimensions admit every rule
- **AND** a free-text search matches a rule whose identifier OR whose comment contains the text

### Requirement: Add-rule modal validates the identifier for its type

The Application Control screen SHALL provide a modal for creating a rule. The modal SHALL offer a rule-type selector carrying every type the rule schema accepts (`CDHASH`, `BINARY`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`), an identifier field, and optional custom-message, custom-URL, comment and severity controls.

The modal SHALL validate the identifier against the format the selected type requires before allowing submission, and SHALL surface a visible error naming the expected format when it does not match. Submission SHALL additionally be gated on a non-empty audit reason, so no rule reaches the deployment without one recorded.

#### Scenario: An identifier that does not match its type is refused

- **GIVEN** the modal is open with a rule type selected
- **WHEN** the operator enters an identifier that does not match that type's format
- **THEN** the modal refuses to submit and shows an error naming the format the type requires

#### Scenario: A valid rule is created with its reason recorded

- **GIVEN** the modal is open with a valid type, a valid identifier and a non-empty audit reason
- **WHEN** the operator submits
- **THEN** the rule is persisted against the policy through the app-control REST surface
- **AND** the audit reason is carried with the request

#### Scenario: Submission is blocked until an audit reason is entered

- **GIVEN** the modal is open with a valid type and a valid identifier
- **WHEN** the audit reason is empty
- **THEN** submission is unavailable until a non-empty reason is entered

### Requirement: Paste-many infers a rule type per line

The Application Control screen SHALL provide a flow that accepts a newline-delimited list of identifiers and infers a rule type for each line from the identifier's shape: 40 lowercase hex characters as `CDHASH`, 64 lowercase hex characters as `BINARY`, ten characters of `[A-Z0-9]` as `TEAMID`, a prefixed signing identity as `SIGNINGID`, and an absolute path as `PATH`.

A 64-character hex value is the SHA-256 of either a Mach-O binary or a leaf certificate, and the shape cannot distinguish them. The flow SHALL therefore mark such a line with a visible hint that it could also be a `CERTIFICATE`.

The operator SHALL be able to override the inferred type on any line before submitting. The flow SHALL NOT submit while any line has no resolved type, and SHALL be gated on a non-empty audit reason, so an ambiguous paste cannot be committed by accident.

#### Scenario: Mixed identifiers are inferred and can be overridden

- **GIVEN** the operator pastes a list containing a 40-hex value, a 64-hex value, a TeamID and an absolute path
- **WHEN** the flow parses the input
- **THEN** each line is shown with the rule type inferred from its shape
- **AND** the 64-hex line carries a visible hint that it could also be a `CERTIFICATE`
- **AND** the operator can change any line's type before submitting

#### Scenario: An unresolved line blocks the whole submission

- **GIVEN** a parsed paste in which at least one line has no resolved rule type
- **WHEN** the operator attempts to submit
- **THEN** submission is refused until every line has a type
