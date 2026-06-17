# Server application control: snapshot epoch delta

## MODIFIED Requirements

### Requirement: Command fan-out on policy mutation

The system SHALL enqueue at most one `set_application_control` command per unique host that belongs to any host group assigned to a mutated policy; hosts that match through multiple groups SHALL NOT receive duplicate commands. The command payload SHALL carry `{policy_id, policy_version, policy_epoch, rules: [...]}` where each rule entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url, severity}`. `policy_epoch` SHALL be the policy's server-assigned `updated_at` timestamp expressed in Unix microseconds (or `0` when the policy carries no timestamp), composed from the same post-mutation policy read that supplies `policy_version`; it is the restore-surviving recency marker the extension uses to re-sync after a database restore regresses `policy_version`. Disabled rules and expired rules SHALL be omitted from the payload. The system SHALL record the count of unique hosts the command was successfully enqueued for and the count of unique hosts the enqueue failed for, and SHALL include those counts on the audit event for the mutation.

#### Scenario: A new rule fans out only to assigned hosts

- **GIVEN** a policy assigned to a host group whose criteria matches three of the deployment's five hosts
- **WHEN** the operator creates a rule on that policy
- **THEN** exactly three `set_application_control` commands are enqueued
- **AND** the audit event records `fanout_hosts=3`, `fanout_failed=0`

#### Scenario: A host that matches multiple assigned groups receives one command

- **GIVEN** a policy assigned to two host groups whose criteria both match the same host
- **WHEN** the system fans out the policy
- **THEN** exactly one `set_application_control` command is enqueued for that host
- **AND** the audit event's `fanout_hosts` counts that host once

#### Scenario: Disabled rules are not pushed

- **GIVEN** a policy with two rules, one of which is `enabled=false`
- **WHEN** the system fans out the policy
- **THEN** the command payload contains only the enabled rule

#### Scenario: The payload carries the policy epoch

- **GIVEN** a policy whose `updated_at` advances on every mutation
- **WHEN** the system composes the `set_application_control` payload after a mutation
- **THEN** the payload's `policy_epoch` equals the policy's post-mutation `updated_at` in Unix microseconds
- **AND** a later mutation produces a payload whose `policy_epoch` is greater, even across a database restore that regressed `policy_version`
