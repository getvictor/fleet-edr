# Server Application Control Specification

## Purpose

The application control subsystem is the EDR's server-side authority for deciding which executables MAY run on enrolled hosts. It owns the durable representation of policies, the rules inside each policy, the host groups those policies are assigned to, the REST surface operators use to author and govern those rules, the command contract that fans a policy snapshot out to hosts as `set_application_control` commands, and the decision-event contract that comes back from the extension when a rule fires. In this phase the only action a rule may take is `BLOCK` and every rule's `enforcement` defaults to `PROTECT`; the engine is shaped so detect-vs-protect rollout, default-deny policies, and per-rule expiry can layer on without a migration.

## Requirements

### Requirement: Policy is a named, versioned ruleset

The system SHALL represent application control as a collection of named policies per deployment. Each policy SHALL carry an immutable identifier, a deployment-unique name, a description, a monotonically increasing version that SHALL be incremented on every mutation of the policy or any of its rules, a default action constrained to `NONE` in this phase, and timestamps and actor identity for the most recent change.

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

The system SHALL represent every rule as a row owned by exactly one policy and carrying: a `rule_type` from the set `{CDHASH, BINARY, SIGNINGID, CERTIFICATE, TEAMID, PATH}`; an `identifier` string whose format is determined by `rule_type`; an `action` constrained in this phase to `BLOCK`; an `enforcement` from `{PROTECT, DETECT}`, with no default; an `enabled` flag; a `severity` from `{low, medium, high, critical}` defaulting to `medium`; a `source` from `{admin, imported, intel}` defaulting to `admin`; an optional `source_ref`; an optional `custom_msg`; an optional `custom_url`; an optional `comment`; an optional `expires_at`; and timestamps and actor identity. The triple `(policy_id, rule_type, identifier)` SHALL be unique.

A `PROTECT` rule denies an exec it matches. A `DETECT` rule blocks nothing: when the policy allows an exec it matches, the host reports the match so it is kept as a monitor record, and a `DETECT` rule never changes the verdict another rule reaches. The changes from the prior requirement are that `DETECT` has a meaning, where before it was stored and no rule could be created with it, and that enforcement no longer defaults to `PROTECT`.

#### Scenario: Two rules in the same policy can target the same identifier under different types

- **GIVEN** a policy that already contains a `BINARY` rule for hash `H`
- **WHEN** the operator adds a `PATH` rule for `/usr/local/bin/H`
- **THEN** the system creates the new rule successfully because the unique key includes `rule_type`

#### Scenario: Duplicating the same `(rule_type, identifier)` is rejected

- **GIVEN** a policy that already contains a `TEAMID` rule for `EQHXZ8M8AV`
- **WHEN** the operator attempts to create a second `TEAMID` rule with the same identifier in the same policy
- **THEN** the system rejects the request with a typed error indicating the rule already exists

### Requirement: Identifier validation per rule type

The system SHALL validate every rule identifier against the format required by its `rule_type` before persisting the rule, and SHALL reject the request with a typed error when the identifier does not match the required format. The validation rules are:

- `CDHASH`: exactly 40 lowercase hexadecimal characters.
- `BINARY`: exactly 64 lowercase hexadecimal characters.
- `CERTIFICATE`: exactly 64 lowercase hexadecimal characters.
- `TEAMID`: exactly 10 characters drawn from `[A-Z0-9]`.
- `SIGNINGID`: either `<TeamID>:<bundle.id>` where `TeamID` matches the `TEAMID` format above, or `platform:<bundle.id>` for Apple platform binaries. The `bundle.id` portion MUST be a non-empty string of ASCII characters drawn from `[A-Za-z0-9._-]`.
- `PATH`: a macOS-canonical absolute path. The system SHALL canonicalize Apple's well-known symlinks (`/tmp`, `/var`, `/etc`) into their `/private/...` forms before persisting.

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

The system SHALL represent host groups as named, deployment-wide objects that describe membership through a criteria document. The system SHALL seed a built-in group named `all-hosts` whose criteria match every host. The system SHALL allow a policy to be assigned to one or more host groups via a join table carrying `(policy_id, host_group_id, priority)`. In this phase only the built-in `all-hosts` group is editable by the system itself; user-authored host groups arrive in a follow-on change.

#### Scenario: A fresh deployment has an all-hosts group and the Default policy is assigned to it

- **GIVEN** a fresh deployment has just been created
- **WHEN** the operator inspects the assignments of the `Default` policy
- **THEN** the assignment list contains exactly the built-in `all-hosts` group

### Requirement: REST surface for policies, rules, groups, and assignments

The system SHALL expose the application control subsystem under `/api/v1/app-control/` with operator session authentication and CSRF protection on every state-changing call. The endpoints SHALL be:

- `GET /api/v1/app-control/policies` and `POST /api/v1/app-control/policies`
- `GET /api/v1/app-control/policies/{id}`, `PATCH /api/v1/app-control/policies/{id}`, `DELETE /api/v1/app-control/policies/{id}`
- `POST /api/v1/app-control/policies/{id}/rules` and `POST /api/v1/app-control/policies/{id}/rules:bulkUpsert`
- `GET /api/v1/app-control/rules/{id}`, `PATCH /api/v1/app-control/rules/{id}`, `DELETE /api/v1/app-control/rules/{id}`, `GET /api/v1/app-control/rules`
- `GET /api/v1/app-control/host-groups`, `POST /api/v1/app-control/host-groups`, `PATCH /api/v1/app-control/host-groups/{id}`, `DELETE /api/v1/app-control/host-groups/{id}`
- `POST /api/v1/app-control/policies/{id}/assignments`

A single rule SHALL be readable by its own id, returning the rule including the identifier of the policy that owns it. That ownership is not otherwise derivable by a client: an application-control alert records the rule it matched, not the policy, so without this read an operator holding an alert cannot reach the policy that blocked.

Successful responses SHALL be JSON. Errors SHALL follow the API capability's `ErrorResponse` shape. Each state-changing endpoint SHALL require a non-empty `actor` and `reason` field in the request body for audit.

#### Scenario: An unauthenticated request is rejected

- **GIVEN** a client without a valid session cookie
- **WHEN** the client calls any endpoint under `/api/v1/app-control/`
- **THEN** the server responds with HTTP 401 and the standard error shape

#### Scenario: A bulk upsert is idempotent on the unique key

- **GIVEN** a policy whose rules were created by a prior `bulkUpsert`
- **WHEN** the operator re-issues the identical `bulkUpsert` payload
- **THEN** the second run inserts zero new rules and updates the matching ones in place, because the `(rule_type, identifier)` unique key makes the upsert idempotent
- **AND** the policy ends with the same rule set

#### Scenario: A single rule is readable by its id

- **GIVEN** an operator with application-control read permission and a rule that exists
- **WHEN** the client calls `GET /api/v1/app-control/rules/{id}` for that rule
- **THEN** the response carries the rule, including the id of the policy that owns it
- **AND** a rule id that names no rule responds 404 with the standard error shape
- **AND** a caller without application-control read permission is refused, whatever the rule id

### Requirement: Rule lifecycle audit events

The system SHALL emit an audit event for every create, update, or delete of a policy or a rule. A rule update that changes nothing is not an update for this purpose and SHALL NOT emit one (see "An unchanged rule update is not a mutation"). The event SHALL include the acting principal (its principal id and a resolvable label, for a human user or a service account alike), the reason supplied with the request, the policy and (for rule events) rule identifier, and a structured diff of the change. The per-row attribution columns (`created_by` / `updated_by`) SHALL store the acting principal id, not a human-only identifier, and a system-originated write SHALL record the system principal (principal id `sys`, type `system`) rather than a free-form literal such as `"system"`. A `bulkUpsert` SHALL emit exactly one audit event covering the logical operation rather than one event per touched rule. A service-account write MUST NOT be rejected at the persistence layer for lacking a human user id.

The change from the prior requirement is the exception for a rule update that changes nothing, which previously fell under "every update".

#### Scenario: Creating a rule records the acting principal

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully creates a rule
- **THEN** the audit log contains a new event with the acting principal id and label, the supplied reason, the policy and rule identifiers, and a diff describing the created rule
- **AND** the rule's `created_by` column stores that principal id

#### Scenario: A service account creates a rule and is attributed

- **GIVEN** an admin-roled service account
- **WHEN** it successfully creates a rule
- **THEN** the write succeeds without an `actor is required` rejection
- **AND** the audit event and the `created_by` column record the service account's principal id

#### Scenario: Bulk upsert emits a single audit event

- **GIVEN** an authenticated operator
- **WHEN** the operator successfully bulk-upserts twenty rules
- **THEN** the audit log gains exactly one event recording the logical operation, the acting principal, and the count of touched rules

### Requirement: Command fan-out on policy mutation

The system SHALL enqueue at most one `set_application_control` command per unique host that belongs to any host group assigned to a mutated policy; hosts that match through multiple groups SHALL NOT receive duplicate commands. The command payload SHALL carry `{policy_id, policy_version, policy_epoch, rules: [...]}` where each rule entry includes `{rule_type, identifier, action, enforcement, custom_msg, custom_url, severity}`. `policy_epoch` SHALL be the policy's server-assigned `updated_at` timestamp expressed in Unix microseconds (or `0` when the policy carries no timestamp), composed from the same post-mutation policy read that supplies `policy_version`; it is the recency marker the extension orders snapshots by first, and the one that re-syncs a host after a database restore regresses `policy_version`, once the database clock is past any epoch the restore lost. Every mutation of a policy SHALL set its `updated_at` to a time strictly later than the previous value, even when the database clock has stepped back, because a host refuses a snapshot whose epoch is not ahead of the one it holds. Disabled rules and expired rules SHALL be omitted from the payload.

The enqueue SHALL be performed in bulk, as a bounded-size multi-row insert rather than one database round trip per host, so that fan-out to the full enrolled fleet completes within a single synchronous operator request even at the deployment's host-count ceiling. The system SHALL record on the mutation's audit event the total count of unique hosts the command was enqueued for (`fanout_hosts`) and the count of those unique hosts whose command did not land (`fanout_failed`). Because a multi-row insert is atomic per statement, when a bulk insert of a set of hosts fails, every unique host in that set SHALL be counted in `fanout_failed`. A fan-out failure SHALL NOT fail the operator's mutation: the policy row is authoritative and any host whose command did not land re-syncs on its next poll.

The change from the prior requirement is that the epoch is forced forward on every mutation rather than left to the column's own update timestamp.

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
- **AND** a later mutation produces a payload whose `policy_epoch` is greater, including after a database restore that regressed `policy_version` once the database clock is past the epochs the restore lost

#### Scenario: The policy epoch advances when the database clock steps back

- **GIVEN** a policy whose `updated_at` is later than the database clock's current time
- **WHEN** the operator creates, updates or deletes a rule, bulk-upserts rules, or updates the policy
- **THEN** the policy's `updated_at` after the mutation is later than it was before

#### Scenario: A failed enqueue batch counts every host in it as failed

- **GIVEN** a policy assigned to a host group matching two hosts
- **WHEN** the operator mutates the policy and the bulk command enqueue for that batch fails
- **THEN** the HTTP mutation still succeeds
- **AND** the audit event records `fanout_failed` equal to the number of hosts in the failed batch

### Requirement: Application control block event contract

The system SHALL accept ingest events of kind `application_control_block` from agents through the same host-token-authenticated `POST /api/events` channel that carries every other agent event. The system MUST bind every accepted event to the `host_id` resolved by the existing host-token middleware and MUST reject events whose envelope `host_id` does not match the authenticated host.

Each event MUST carry `pid`, `path`, `policy_id`, `policy_version`, `rule_id`, `rule_type`, `identifier`, and `severity`. The event MAY carry `custom_msg` and `custom_url`, which are absent rather than null when the matched rule does not set them. The `identifier` is the value from the target tuple that actually matched, not the rule's own stored identifier, so an operator reading the alert sees which of the process's identities was the one that hit.

The system SHALL accept events whose `policy_id` or `rule_id` does not correspond to a known rule (so an in-flight block is not lost when a rule is deleted after the block fired).

#### Scenario: A block event for an unknown rule is accepted

- **GIVEN** an agent posts an `application_control_block` event whose `rule_id` does not exist
- **WHEN** the server ingests the event
- **THEN** the server responds with HTTP 200 and the event is persisted

#### Scenario: A block event for a now-deleted rule is accepted

- **GIVEN** a rule that existed when the agent denied the exec but was deleted before the event reached the server
- **WHEN** the agent posts the `application_control_block` event
- **THEN** the server accepts and persists the event so the historical decision is not lost

### Requirement: Bootstrap seeds Default policy and all-hosts group

The system SHALL ensure that, on first server boot, the application control bootstrap produces exactly one host group named `all-hosts` whose criteria match every host, exactly one policy named `Default` with zero rules and `default_action='NONE'`, with the `Default` policy assigned to the `all-hosts` group. The bootstrap MUST be idempotent across repeated server starts.

#### Scenario: A fresh database boots into a usable state

- **GIVEN** a fresh database
- **WHEN** the server completes its bootstrap
- **THEN** the deployment has exactly one host group named `all-hosts`, exactly one policy named `Default`, and exactly one assignment connecting them

#### Scenario: Bootstrap is idempotent

- **GIVEN** a database that has already been bootstrapped
- **WHEN** the server starts again
- **THEN** the host group, policy, and assignment counts remain at one each

### Requirement: An unchanged rule update is not a mutation

A `PATCH /api/v1/app-control/rules/{id}` for an existing rule whose supplied fields all equal the rule's current values SHALL succeed and return the rule. Because nothing changed, it SHALL NOT increment the policy version, enqueue `set_application_control` commands, or emit an audit event. A `PATCH` that changes at least one field SHALL remain a mutation, whatever the other fields it supplies. A `PATCH` for a rule that does not exist, including one deleted while the request was in flight, SHALL fail with `application_control.rule_not_found`.

#### Scenario: An unchanged update returns the rule

- **GIVEN** a rule with enforcement `PROTECT` and severity `medium`, in a policy at version `N`
- **WHEN** an operator sends a `PATCH` setting enforcement to `PROTECT` and severity to `medium`
- **THEN** the response is 200 with the rule
- **AND** the policy is still at version `N`, no `set_application_control` command is enqueued, and no audit event is recorded

#### Scenario: Changing one field is a mutation

- **GIVEN** a rule with enforcement `PROTECT` and severity `medium`
- **WHEN** an operator sends a `PATCH` setting enforcement to `PROTECT` and severity to `high`
- **THEN** the rule's severity is `high`, the policy version increments, the snapshot fans out, and an audit event is recorded

### Requirement: Rule enforcement is required and changeable

The rule-create endpoint SHALL require an `enforcement` of `PROTECT` or `DETECT`, and so SHALL every item of a bulk upsert. A rule SHALL NOT take an enforcement by default: `PROTECT` blocks and `DETECT` only records, and either one chosen silently is wrong for the caller who meant the other. A request that omits it SHALL be rejected with a validation error naming the missing field. A bulk upsert that updates an existing rule SHALL set that rule's enforcement to the one the item names. The rule-update endpoint SHALL accept `enforcement` as a mutable field, which is how an operator promotes a `DETECT` rule to `PROTECT` or moves it back. Every endpoint SHALL reject any other value with a validation error and SHALL change nothing. A change of enforcement SHALL bump the policy version and push the new snapshot to the policy's hosts like any other rule mutation, and the create and update audit events SHALL record the rule's enforcement.

#### Scenario: A rule created in DETECT reaches hosts in DETECT

- **GIVEN** an operator creating a rule with `enforcement=DETECT`
- **WHEN** the request succeeds
- **THEN** the stored rule's enforcement is `DETECT`
- **AND** the snapshot pushed to the policy's hosts carries the rule with `enforcement=DETECT`
- **AND** the audit event records `DETECT`

#### Scenario: A rule created without an enforcement is rejected

- **GIVEN** an operator creating a rule without an `enforcement` field
- **WHEN** the request is handled
- **THEN** the server responds with HTTP 400 saying enforcement is required
- **AND** no rule is created

#### Scenario: A bulk upsert names each rule's enforcement

- **GIVEN** a bulk upsert with an item that has no `enforcement`
- **WHEN** the request is handled
- **THEN** the whole batch is rejected and nothing is stored
- **AND** once every item names one, each rule is stored with its item's enforcement
- **AND** re-upserting an existing rule with a different enforcement updates it

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

### Requirement: Concurrent rule changes to one policy serialize

Rule mutations that touch the same policy SHALL serialize against one another rather than fail. Each one changes two things, the rule and the policy version that makes the change visible to hosts, and the system SHALL acquire them in one order for every mutation. Approaching the same two rows from opposite ends leaves each writer holding what the other needs, and the database resolves that by aborting one of them, which reaches the operator as a failed request for a change that was valid.

The order SHALL be the policy first. That is the row every rule mutation has in common, so locking it first is what makes the set of mutations a queue rather than a race; a create additionally takes a shared lock on that row as a consequence of the rule referencing it, and must therefore already hold the stronger one.

Serializing per policy SHALL NOT extend to different policies, which have no row in common and no reason to wait for each other.

A mutation naming a policy or a rule that does not exist SHALL be reported as not found, and SHALL be reported that way whether the absence is discovered while ordering the locks or afterwards. A database that cannot answer SHALL NOT be reported that way: an operator told their rule is gone believes someone else deleted it, which is a different event from a change that failed and can be retried.

#### Scenario: Concurrent rule creates do not deadlock

- **GIVEN** a policy
- **WHEN** several operators create rules in it at the same time
- **THEN** every create either succeeds or fails for its own reason
- **AND** none fails because the database aborted it to resolve a deadlock

#### Scenario: A single-rule change and a bulk upsert do not deadlock

- **GIVEN** a policy holding rules
- **WHEN** single-rule changes and a bulk upsert of the same policy run at the same time
- **THEN** each completes or fails on its own merits
- **AND** none fails because the database aborted it to resolve a deadlock

#### Scenario: A rule change waits for whoever holds the policy

- **GIVEN** a policy another writer is already holding
- **WHEN** an operator changes a rule in that policy
- **THEN** the change waits for the holder rather than proceeding beside it
- **AND** a wait that runs out is reported as a failed change, not as a missing rule

#### Scenario: A database that cannot answer is not a missing rule

- **GIVEN** a rule whose policy cannot be read because the database fails
- **WHEN** an operator changes that rule
- **THEN** the failure is reported as a failure
- **AND** not as the rule having been deleted
