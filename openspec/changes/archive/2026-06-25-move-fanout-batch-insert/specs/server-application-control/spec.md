# Server application control: batched fan-out delta

## MODIFIED Requirements

### Requirement: Command fan-out on policy mutation

The system SHALL enqueue at most one `set_application_control` command per unique host that belongs to any host group assigned to a mutated policy; hosts that match through multiple groups SHALL NOT receive duplicate commands. The command payload SHALL carry `{policy_id, policy_version, policy_epoch, rules: [...]}` where each rule entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url, severity}`. `policy_epoch` SHALL be the policy's server-assigned `updated_at` timestamp expressed in Unix microseconds (or `0` when the policy carries no timestamp), composed from the same post-mutation policy read that supplies `policy_version`; it is the restore-surviving recency marker the extension uses to re-sync after a database restore regresses `policy_version`. Disabled rules and expired rules SHALL be omitted from the payload.

The enqueue SHALL be performed in bulk, as a bounded-size multi-row insert rather than one database round trip per host, so that fan-out to the full enrolled fleet completes within a single synchronous operator request even at the deployment's host-count ceiling. The system SHALL record on the mutation's audit event the total count of unique hosts the command was enqueued for (`fanout_hosts`) and the count of those unique hosts whose command did not land (`fanout_failed`). Because a multi-row insert is atomic per statement, when a bulk insert of a set of hosts fails, every unique host in that set SHALL be counted in `fanout_failed`. A fan-out failure SHALL NOT fail the operator's mutation: the policy row is authoritative and any host whose command did not land re-syncs on its next poll.

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

#### Scenario: A failed enqueue batch counts every host in it as failed

- **GIVEN** a policy assigned to a host group matching two hosts
- **WHEN** the operator mutates the policy and the bulk command enqueue for that batch fails
- **THEN** the HTTP mutation still succeeds
- **AND** the audit event records `fanout_failed` equal to the number of hosts in the failed batch
