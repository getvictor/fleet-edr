## MODIFIED Requirements

### Requirement: Signature-based parent exclusions

The `suspicious_exec` rule SHALL suppress a finding when the chain's non-shell parent process matches an operator exclusion by its code-signing identity, in addition to the existing parent-path-glob match. The consulted signature dimensions are the parent's Apple Developer team ID (`team_id`), its code-signing identifier (`signing_id`), and its code-directory hash (`cdhash`), read from the parent process's already-persisted code-signing record; no agent or event-wire change is required.

A `signing_id` exclusion SHALL name the identifier QUALIFIED by who signed it: `<TEAMID>:<identifier>`, or `platform:<identifier>` for a binary the operating system vendor ships. Both parts SHALL match. A parent that carries an identifier but no team ID and is not a platform binary SHALL NOT be suppressed by any `signing_id` exclusion.

The identifier alone is not an identity: an ad-hoc signature sets it to any value with no privilege and no vendor account, so an unqualified match let a planted binary inherit the exclusion written for the vendor whose identifier it claimed. The system SHALL refuse an unqualified `signing_id` exclusion value when it is created, naming the expected form, because an exclusion that can never match is one an operator believes is suppressing something. A finding with no resolved non-shell parent, or a parent that carries no signing identity, MUST NOT be suppressed by a signature exclusion, so an unsigned binary at a benign-looking path is not silently allowed. This lets an operator exclude a code-signed developer tool by a signing identity a planted binary cannot claim, instead of a path glob that an attacker who can write to a world-writable directory could land inside.

#### Scenario: A signed parent is suppressed by its team ID

- **GIVEN** a `suspicious_exec` chain whose non-shell parent is a code-signed binary with team ID `Q6L2SF6YDW`
- **AND** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the parent's signing team ID matches the exclusion
- **AND** the same holds for a `signing_id` exclusion whose value is that team ID and the parent's signing identifier, and a `cdhash` exclusion matching the parent's code-directory hash

#### Scenario: An unsigned lookalike parent is not suppressed

- **GIVEN** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **AND** a `suspicious_exec` chain whose non-shell parent is an unsigned binary at a path resembling the benign tool (for example `/tmp/claude/versions/1.0/claude`)
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the finding is produced, because the unsigned parent carries no team ID for the signature exclusion to match

#### Scenario: An ad-hoc parent claiming an identifier is not suppressed

- **GIVEN** an exclusion of match type `signing_id` with value `Q6L2SF6YDW:com.anthropic.claude-code` for `suspicious_exec`
- **AND** a chain whose non-shell parent is an ad-hoc signed binary carrying that identifier, with no team ID and no platform flag
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the finding is produced, because the identifier is whatever the signer typed and nothing vouches for it

#### Scenario: A platform binary is suppressed by a platform-qualified value

- **GIVEN** an exclusion of match type `signing_id` with value `platform:com.apple.osascript` for `suspicious_exec`
- **AND** a chain whose non-shell parent is a platform binary carrying that identifier and no team ID
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no finding, because the platform flag is the qualifier the operating system's own binaries carry

#### Scenario: A bare signing id exclusion is refused

- **GIVEN** an operator creating a `signing_id` exclusion whose value is a bare identifier
- **WHEN** the request is made
- **THEN** it is rejected as an invalid request, naming both accepted forms
- **AND** nothing is stored
