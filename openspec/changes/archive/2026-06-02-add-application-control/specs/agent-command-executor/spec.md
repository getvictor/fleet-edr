# Agent Command Executor Specification (delta)

## ADDED Requirements

### Requirement: Set-application-control command

The system SHALL execute a `set_application_control` command by forwarding the typed rule snapshot to the
local Endpoint Security extension and SHALL report the policy identifier and version that were forwarded so
the server can confirm per-host convergence. The payload SHALL carry `{policy_id, policy_version, rules}`
where each `rules` entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url,
severity}`. The executor SHALL validate that `policy_id` is non-empty and `policy_version` is positive
before forwarding.

#### Scenario: Forwarded successfully

- **GIVEN** a `set_application_control` command is received with a non-empty `policy_id`, a positive
  `policy_version`, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the executor reports completed with the policy identifier, the policy version, and the count of
  rules in the payload

#### Scenario: Extension bridge is not available

- **GIVEN** the agent has no configured extension bridge
- **WHEN** a `set_application_control` command is received
- **THEN** the executor reports failed with a reason identifying the missing bridge
- **AND** no other side effect is performed

#### Scenario: Payload is missing required fields or has a non-positive version

- **GIVEN** a `set_application_control` command is received whose payload is missing `policy_id`, missing
  `policy_version`, or whose `policy_version` is zero or negative
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid payload
- **AND** the extension bridge is not invoked

#### Scenario: A rules entry has an unknown rule type

- **GIVEN** a `set_application_control` payload whose `rules` array contains a `rule_type` not in
  `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the unknown rule type
- **AND** the extension bridge is not invoked

## REMOVED Requirements

### Requirement: Set-blocklist command

**Reason**: Replaced by the `set_application_control` command, which carries typed rules rather than two
flat arrays of paths and SHA-256 hashes and which carries policy identity. The product has not shipped its
first release, so no compatibility shim is added.

**Migration**: None. The legacy `set_blocklist` command type is deleted from the agent in the same change
that adds `set_application_control`.
