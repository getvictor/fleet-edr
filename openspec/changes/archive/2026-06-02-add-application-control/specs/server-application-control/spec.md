# Server Application Control Specification

## Purpose

The application control subsystem is the EDR's server-side authority for deciding which executables MAY run on
enrolled hosts. It owns the durable representation of policies, the rules inside each policy, the host groups
those policies are assigned to, the contract for the agent command that pushes a policy snapshot to a host, and
the contract for the decision events that come back from the extension when a rule fires. It is the surface that
operators (and, in later phases, integrations and threat-intel feeds) interact with to author and govern those
rules.

In this phase the only action a rule may take is `BLOCK`; allowlists, default-deny policies, detect-vs-protect
enforcement, simulation against historical telemetry, and per-rule expiry semantics arrive in a follow-on change.
The schema is shaped so that none of those additions requires a migration.

## ADDED Requirements

### Requirement: Policy is a named, versioned ruleset

The system SHALL represent application control as a collection of named policies per deployment. Each policy
SHALL carry an immutable identifier, a deployment-unique name, a description, a monotonically increasing
version that SHALL be incremented on every mutation of the policy or any of its rules, a default action
constrained to `NONE` in this phase, and timestamps and actor identity for the most recent change.

#### Scenario: A fresh deployment boots and the seed policy is present

- **GIVEN** a fresh deployment has just been created
- **WHEN** the operator lists application control policies
- **THEN** the response includes a built-in policy named `Default` with zero rules and `default_action='NONE'`

#### Scenario: Creating a rule increments the policy version

- **GIVEN** a policy at version `N`
- **WHEN** an operator creates a rule in that policy
- **THEN** the policy version is `N+1`
- **AND** the policy `updated_at` and `updated_by` reflect the change

#### Scenario: Two policies cannot share a name

- **GIVEN** a deployment already has a policy named `Engineering`
- **WHEN** the operator attempts to create a second policy named `Engineering`
- **THEN** the system rejects the request with a typed error indicating the name is already in use

### Requirement: Rule identifies one binary, signing identity, or path

The system SHALL represent every rule as a row owned by exactly one policy and carrying: a `rule_type` from
the set `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`; an `identifier` string whose format is
determined by `rule_type`; an `action` constrained in this phase to `BLOCK`; an `enforcement` from
`{PROTECT, DETECT}` defaulting to `PROTECT`; an `enabled` flag; a `severity` from
`{low, medium, high, critical}` defaulting to `medium`; a `source` from `{admin, imported, intel}` defaulting
to `admin`; an optional `source_ref`; an optional `custom_msg`; an optional `custom_url`; an optional
`comment`; an optional `expires_at`; and timestamps and actor identity. The triple
`(policy_id, rule_type, identifier)` SHALL be unique.

#### Scenario: Two rules in the same policy can target the same identifier under different types

- **GIVEN** a policy that already contains a `BINARY` rule for hash `H`
- **WHEN** the operator adds a `PATH` rule for `/usr/local/bin/H`
- **THEN** the system creates the new rule successfully because the unique key includes `rule_type`

#### Scenario: Duplicating the same `(rule_type, identifier)` is rejected

- **GIVEN** a policy that already contains a `TEAMID` rule for `EQHXZ8M8AV`
- **WHEN** the operator attempts to create a second `TEAMID` rule with the same identifier in the same policy
- **THEN** the system rejects the request with a typed error indicating the rule already exists

### Requirement: Identifier validation per rule type

The system SHALL validate every rule identifier against the format required by its `rule_type` before
persisting the rule, and SHALL reject the request with a typed error when the identifier does not match the
required format. The validation rules are:

- `CDHASH`: exactly 40 lowercase hexadecimal characters.
- `BINARY`: exactly 64 lowercase hexadecimal characters.
- `CERTIFICATE`: exactly 64 lowercase hexadecimal characters.
- `TEAMID`: exactly 10 characters drawn from `[A-Z0-9]`.
- `SIGNINGID`: either `<TeamID>:<bundle.id>` where `TeamID` matches the `TEAMID` format above, or
  `platform:<bundle.id>` for Apple platform binaries. The `bundle.id` portion MUST be a non-empty string of
  ASCII characters drawn from `[A-Za-z0-9._-]`.
- `PATH`: a macOS-canonical absolute path. The system SHALL canonicalize Apple's well-known symlinks (`/tmp`,
  `/var`, `/etc`) into their `/private/...` forms before persisting.

#### Scenario: A TeamID with the wrong length is rejected

- **GIVEN** an operator submits a rule with `rule_type=TEAMID` and `identifier="ABC"`
- **WHEN** the server validates the request
- **THEN** the server responds with a typed error indicating the identifier is invalid for the rule type

#### Scenario: A platform SigningID is accepted

- **GIVEN** an operator submits a rule with `rule_type=SIGNINGID` and `identifier="platform:com.apple.curl"`
- **WHEN** the server validates the request
- **THEN** the server persists the rule

#### Scenario: A path is canonicalized before persistence

- **GIVEN** an operator submits a rule with `rule_type=PATH` and `identifier="/tmp/foo"`
- **WHEN** the server persists the rule
- **THEN** the stored identifier is `/private/tmp/foo`

### Requirement: Host groups and policy assignments

The system SHALL represent host groups as named, deployment-wide objects that describe membership through a
criteria document. The system SHALL seed a built-in group named `all-hosts` whose criteria match every host.
The system SHALL allow a policy to be assigned to one or more host groups via a join table carrying
`(policy_id, host_group_id, priority)`. In this phase only the built-in `all-hosts` group is editable by the
system itself; user-authored host groups arrive in a follow-on change.

#### Scenario: A fresh deployment has an all-hosts group and the Default policy is assigned to it

- **GIVEN** a fresh deployment has just been created
- **WHEN** the operator inspects the assignments of the `Default` policy
- **THEN** the assignment list contains exactly the built-in `all-hosts` group

### Requirement: REST surface for policies, rules, groups, and assignments

The system SHALL expose the application control subsystem under `/api/v1/app-control/` with operator session
authentication and CSRF protection on every state-changing call. The endpoints SHALL be:

- `GET /api/v1/app-control/policies` and `POST /api/v1/app-control/policies`
- `GET /api/v1/app-control/policies/{id}`, `PATCH /api/v1/app-control/policies/{id}`,
  `DELETE /api/v1/app-control/policies/{id}`
- `POST /api/v1/app-control/policies/{id}/rules` and
  `POST /api/v1/app-control/policies/{id}/rules:bulkUpsert`
- `PATCH /api/v1/app-control/rules/{id}`, `DELETE /api/v1/app-control/rules/{id}`,
  `GET /api/v1/app-control/rules`
- `GET /api/v1/app-control/host-groups`, `POST /api/v1/app-control/host-groups`,
  `PATCH /api/v1/app-control/host-groups/{id}`, `DELETE /api/v1/app-control/host-groups/{id}`
- `POST /api/v1/app-control/policies/{id}/assignments`

Successful responses SHALL be JSON. Errors SHALL follow the API capability's `ErrorResponse` shape. Each
state-changing endpoint SHALL require a non-empty `actor` and `reason` field in the request body for audit.

#### Scenario: An unauthenticated request is rejected

- **GIVEN** a client without a valid session cookie
- **WHEN** the client calls any endpoint under `/api/v1/app-control/`
- **THEN** the server responds with HTTP 401 and the standard error shape

#### Scenario: A bulk upsert is idempotent on the unique key

- **GIVEN** a policy with no rules
- **WHEN** the operator issues a `bulkUpsert` request containing the same rule twice
- **THEN** the policy ends with exactly one rule whose identifier matches
- **AND** the operation succeeds

### Requirement: Rule lifecycle audit events

The system SHALL emit an audit event for every create, update, or delete of a policy or a rule. The event
SHALL include the actor, the reason supplied with the request, the policy and (for rule events) rule
identifier, and a structured diff of the change. A `bulkUpsert` SHALL emit exactly one audit event covering
the logical operation rather than one event per touched rule.

#### Scenario: Creating a rule emits an audit event

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully creates a rule
- **THEN** the audit log contains a new event with the operator's identity, the supplied reason, the policy
  and rule identifiers, and a diff describing the created rule

#### Scenario: Bulk upsert emits a single audit event

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully bulk-upserts twenty rules
- **THEN** the audit log gains exactly one event recording the logical operation and the count of touched
  rules

### Requirement: Command fan-out on policy mutation

The system SHALL enqueue at most one `set_application_control` command per unique host that belongs to any
host group assigned to a mutated policy; hosts that match through multiple groups SHALL NOT receive duplicate
commands. The command payload SHALL carry `{policy_id, policy_version, rules: [...]}` where each rule entry
includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url, severity}`. Disabled rules and
expired rules SHALL be omitted from the payload. The system SHALL record the count of unique hosts the
command was successfully enqueued for and the count of unique hosts the enqueue failed for, and SHALL
include those counts on the audit event for the mutation.

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

### Requirement: Application control block event contract

The system SHALL accept ingest events of kind `application_control_block` from agents through the same
host-token-authenticated `POST /api/events` channel that carries every other agent event. The system MUST
bind every accepted event to the `host_id` resolved by the existing host-token middleware and MUST reject
events whose envelope `host_id` does not match the authenticated host. Each event MUST carry `policy_id`,
`policy_version`, `rule_id`, `rule_type`, `rule_identifier`,
`matched_identifier`, `severity`, `process`, and `ancestry`. The event MAY carry optional `custom_msg` and
`custom_url`. The system SHALL accept events whose `policy_id` or `rule_id` does not correspond to a known
rule (so an in-flight block is not lost when a rule is deleted after the block fired) and SHALL log a
server-side warning for operator visibility on the unknown-rule path.

#### Scenario: A block event for an unknown rule is accepted but warned

- **GIVEN** an agent posts an `application_control_block` event whose `rule_id` does not exist
- **WHEN** the server ingests the event
- **THEN** the server responds with HTTP 200
- **AND** the server emits a structured warning identifying the unknown rule id

#### Scenario: A block event for a now-deleted rule is accepted

- **GIVEN** a rule that existed when the agent denied the exec but was deleted before the event reached the
  server
- **WHEN** the agent posts the `application_control_block` event
- **THEN** the server accepts and persists the event so the historical decision is not lost

### Requirement: Bootstrap seeds Default policy and all-hosts group

The system SHALL ensure that, on first server boot, the application control bootstrap produces exactly one
host group named `all-hosts` whose criteria match every host, exactly one policy named `Default` with zero
rules and `default_action='NONE'`, with the `Default` policy assigned to the `all-hosts` group. The bootstrap
MUST be idempotent across repeated server starts.

#### Scenario: A fresh database boots into a usable state

- **GIVEN** a fresh database
- **WHEN** the server completes its bootstrap
- **THEN** the deployment has exactly one host group named `all-hosts`, exactly one policy named `Default`,
  and exactly one assignment connecting them

#### Scenario: Bootstrap is idempotent

- **GIVEN** a database that has already been bootstrapped
- **WHEN** the server starts again
- **THEN** the host group, policy, and assignment counts remain at one each
