# Agent command executor

## MODIFIED Requirements

### Requirement: Set-application-control command

The system SHALL execute a `set_application_control` command by forwarding the typed rule snapshot to the
local Endpoint Security extension and SHALL report the policy identifier and version that were forwarded so
the server can confirm per-host convergence. The payload SHALL carry `{policy_id, policy_version, rules}`
where each `rules` entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url,
severity}`. The executor SHALL validate, before forwarding, that `policy_id` is a positive integer, that
`policy_version` is a positive integer, and that `rules` is a JSON array. It SHALL NOT validate the shape of
the individual entries: the extension owns the rule shape, and the agent forwards the raw payload bytes so
the wire shape stays byte-identical across server, agent, and extension.

#### Scenario: Forwarded successfully

- **GIVEN** a `set_application_control` command is received with a positive `policy_id`, a positive
  `policy_version`, a `rules` array, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the executor reports completed with the policy identifier, the policy version, and the count of
  rules in the payload

#### Scenario: Extension bridge is not available

- **GIVEN** the agent has no configured extension bridge
- **WHEN** a `set_application_control` command is received
- **THEN** the executor reports failed with a reason identifying the missing bridge
- **AND** no other side effect is performed

#### Scenario: Payload is missing required fields or carries a non-positive value

- **GIVEN** a `set_application_control` command is received whose payload has a `policy_id` or a
  `policy_version` that is absent, zero, or negative, or whose `rules` is absent or is not a JSON array
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid payload
- **AND** the extension bridge is not invoked

An entry whose `rule_type` the executor does not recognise SHALL NOT fail the payload. The executor SHALL forward the snapshot, and the extension SHALL apply the entries it understands and skip the rest.

Rejecting the whole payload was specified and is wrong, which is why this says so rather than leaving the requirement silent. `rule_type` is already validated by the server when the rule is created, so the case only arises where the agent is OLDER than the server that wrote the policy. Failing there converts an additive server change into a loss of application control on every host still running the previous agent: no rules apply, rather than the rules that agent understands. Partial enforcement with a warning is the better failure, and it is what the extension already does.
