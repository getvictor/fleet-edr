# Server Admin Surface Specification

## Purpose

The server admin surface is the operator's API into the Fleet EDR control plane. It exposes the endpoints the admin UI and any externally scripted tooling rely on: enumerating enrolled hosts, revoking a host's credentials, reading and mutating the application-control policies + rules that fan out to enrolled hosts, and rendering the detection content (per-rule documentation and ATT&CK technique coverage) that buyers and SOC analysts compare against. It is the only documented way for a human operator to change runtime state on the server.

This specification fixes the HTTP contract: paths, methods, request and response shapes, auth boundary, and the audit trail every state-changing call leaves behind, so the UI, integration scripts, and post-incident reviewers can reason about admin behaviour without reading the handler source.

## Requirements

### Requirement: Authenticated admin boundary

The server MUST gate every endpoint defined by this capability (`/api/enrollments`, `/api/enrollments/{host_id}/revoke`, every route under the `/api/v1/app-control/*` prefix including the `policies`, `policies/{id}/rules`, `policies/{id}/rules:bulkUpsert`, `rules`, `host-groups`, and `policies/{id}/assignments` sub-paths for all HTTP methods, `/api/attack-coverage`, and `/api/rules`) behind the operator-session middleware, so a caller that is not authenticated as an operator SHALL receive `401 Unauthorized`. These endpoints share an authentication boundary with the rest of the operator API; there is no separate "admin" auth mode in the current implementation. The host-groups and assignments sub-resources are present on the wire but their CRUD contracts are not specified in this document; they inherit the auth boundary above.

#### Scenario: Unauthenticated request is rejected

- **GIVEN** a client that has not authenticated
- **WHEN** the client requests any endpoint defined by this capability
- **THEN** the server returns `401 Unauthorized`
- **AND** the response body uses the standard error shape `{"error": "..."}`

#### Scenario: Authenticated admin request proceeds

- **GIVEN** a client holding a valid admin session cookie
- **WHEN** the client requests an admin endpoint and satisfies any required CSRF check for the HTTP method
- **THEN** the request is dispatched to the corresponding admin handler

### Requirement: List enrollments

The system SHALL expose `GET /api/enrollments` returning the set of enrolled hosts known to the server. Each entry MUST identify the host and carry the metadata needed for the admin host list (host id, hostname, agent version, OS version, last-seen timestamp, enrollment status).

#### Scenario: Operator lists enrolled hosts

- **GIVEN** at least one host has enrolled successfully
- **WHEN** the operator requests `GET /api/enrollments`
- **THEN** the server returns `200 OK` with a JSON array of enrollment rows
- **AND** every row includes the host id and the host's last-seen timestamp

### Requirement: Revoke a host enrollment

The system SHALL expose `POST /api/enrollments/{host_id}/revoke` to invalidate a host's bearer token immediately. The request body MUST carry an operator-supplied `reason` and `actor`; the server MUST reject the request when either is empty. Once revoked, the next authenticated request from that host's agent MUST receive `401 Unauthorized`.

#### Scenario: Revoke a known host

- **GIVEN** a host with a currently valid enrollment
- **WHEN** the operator POSTs to `/api/enrollments/{host_id}/revoke` with a non-empty `reason` and `actor`
- **THEN** the server returns `204 No Content`
- **AND** the host's bearer token is invalidated server-side
- **AND** the next request that agent makes with that token receives `401 Unauthorized`

#### Scenario: Revoke without an actor or reason

- **GIVEN** an authenticated operator
- **WHEN** the operator POSTs a revoke request whose body is missing `actor` or `reason`
- **THEN** the server returns `400 Bad Request` and does not modify the enrollment

#### Scenario: Revoke a host that does not exist

- **GIVEN** a host id that does not correspond to any enrollment
- **WHEN** the operator POSTs to revoke that host id
- **THEN** the server returns `404 Not Found`

### Requirement: Read application-control policies

The system SHALL expose `GET /api/v1/app-control/policies` returning the list of application-control policies known to the server. The list response MUST NOT inline the `rules` field for each policy (it is omitted from the list shape to keep the index endpoint cheap); each entry carries the policy's `id`, `name`, `description`, `version`, and `created_at` / `updated_at` audit timestamps plus an assignment count. The system SHALL also expose `GET /api/v1/app-control/policies/{id}` returning a single policy by id with its `rules` array inlined. The seed pass creates a default policy on first boot; reading the list before any operator change MUST surface that default policy.

#### Scenario: First-query returns the seeded default policy

- **GIVEN** a server that has never had an operator-driven policy mutation
- **WHEN** the operator requests `GET /api/v1/app-control/policies`
- **THEN** the server returns `200 OK`
- **AND** the response includes the seeded default policy with its `id`, `name`, and `version` set

#### Scenario: Read after operator changes

- **GIVEN** the operator has previously created at least one application-control rule on a policy
- **WHEN** the operator requests `GET /api/v1/app-control/policies/{id}` for that policy
- **THEN** the response carries the latest persisted `version` and inlines the policy's `rules` array with the operator's changes reflected

### Requirement: Persist and fan out application-control rules

The system SHALL expose `POST /api/v1/app-control/policies/{id}/rules`, `PATCH /api/v1/app-control/rules/{id}`, and `DELETE /api/v1/app-control/rules/{id}` that atomically apply the requested mutation and bump the owning policy's `version`. The system SHALL attempt to queue a `set_application_control` command carrying the post-bump policy state for every active host assigned to the policy, on a best-effort basis. A failure to enqueue the command for an individual host MUST NOT roll back the rule mutation; the server MUST log the per-host fan-out failures so the next agent poll or admin push can reconcile, and MUST record the fan-out count in the audit payload.

Every mutation request body MUST carry a non-empty `reason`. The operator identity (`actor`) is NOT carried in the body; it is derived from the authenticated session context and recorded in the audit row in the form `user:<id>`. The POST (create) body MUST additionally carry `rule_type` and `identifier`; PATCH and DELETE accept partial mutations against the existing rule and do not need either. `rule_type` MUST be one of the supported uppercase tokens: `BINARY`, `CDHASH`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`. `identifier` MUST satisfy the format rules for the declared `rule_type`:

- `BINARY`: 64 lowercase hex characters (SHA-256 of the executable file).
- `CDHASH`: 40 lowercase hex characters (Code Directory hash).
- `SIGNINGID`: `<TeamID>:<bundle.id>` or `platform:<bundle.id>` for Apple platform binaries.
- `CERTIFICATE`: 64 lowercase hex characters (SHA-256 of the leaf X.509 signing certificate; same value `codesign -d --extract-certificates` + `shasum -a 256` against the index-0 cert produces).
- `TEAMID`: 10-character alphanumeric Apple Developer Team ID (e.g. `EQHXZ8M8AV`).
- `PATH`: absolute canonical filesystem path. The validator normalises redundant slashes and rewrites the macOS `/tmp`, `/var`, `/etc` symlinks into their `/private/...` forms; relative paths, empty strings, and paths containing `..` segments are rejected.

A request that violates the rule-type or identifier constraints MUST be rejected with `400 Bad Request` and the policy MUST NOT be modified.

#### Scenario: Valid rule create increments version and fans out

- **GIVEN** a current policy at version `v`
- **WHEN** the operator POSTs a valid rule with a non-empty `reason`
- **THEN** the server returns `201 Created` carrying the new rule
- **AND** the owning policy's `version` has bumped to `v+1` (observable via a subsequent `GET /api/v1/app-control/policies/{id}`)
- **AND** the server attempts to queue a `set_application_control` command for every active host assigned to the policy
- **AND** any host whose enqueue fails is logged so a subsequent reconcile can resend

#### Scenario: Invalid identifier is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator POSTs a rule whose `identifier` violates the format rules for the declared `rule_type` (e.g., a non-hex string for `rule_type=BINARY`, or a string longer than 10 characters for `rule_type=TEAMID`)
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Unsupported rule type is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator POSTs a rule whose `rule_type` is not a member of the supported set (an unknown uppercase token, e.g. `BANANA`; the supported set is `BINARY`, `CDHASH`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`)
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Missing actor or reason is rejected

- **GIVEN** an authenticated operator
- **WHEN** a rule mutation reaches the store layer with either an empty `reason` (which the HTTP handler forwards from the request body) or an empty server-supplied `actor` identifier (a session-middleware bug)
- **THEN** the store returns `ErrAppControlInvalidRequest`, which the HTTP handler maps to `400 Bad Request`, and the policy MUST NOT be modified

### Requirement: Audit trail for state-changing admin actions

The system SHALL maintain a structured, queryable audit trail for state-changing admin actions, as detailed below. Every successful state-changing admin call defined by this specification (revoke, and application-control rule create / update / delete) SHALL emit a structured audit log record carrying at minimum a timestamp, the operator's identity (`actor`, sourced from the session context as `user:<id>` for application-control mutations), the operator-supplied `reason` from the request body, the action name, and either the affected host id (for revoke) or the affected rule id + post-bump policy version + fan-out count (for application-control rule mutations). The audit record MUST be emitted at a level that downstream SIEM and SigNoz queries can filter on so SOC teams can reconstruct who changed what and when. The implementation also emits audit rows for policy CRUD endpoints exposed under `/api/v1/app-control/policies` (create, update, delete); those flows are not specified in this document.

#### Scenario: Revoke produces an audit record

- **GIVEN** an operator who successfully revokes a host
- **WHEN** the revoke completes
- **THEN** a structured log record is emitted carrying the operator's `actor`, the operator's `reason`, the host id, and the action identifier `revoke`

#### Scenario: Rule update produces an audit record

- **GIVEN** an operator who successfully PATCHes an existing application-control rule
- **WHEN** the update commits and the fan-out completes
- **THEN** a structured audit record is emitted carrying the operator's `actor`, the operator's `reason`, the affected rule id, the post-bump policy version, and the count of active hosts the `set_application_control` command was fanned out to

### Requirement: ATT&CK coverage layer endpoint

The system SHALL expose `GET /api/attack-coverage` returning a MITRE ATT&CK Navigator layer JSON document that enumerates the techniques covered by the registered detection rules. The document MUST be importable directly into the upstream MITRE ATT&CK Navigator. Each covered technique MUST identify the rule (or rules) that cover it. The document MUST scope the rendered matrix to the macOS platform via a `filters.platforms` array containing `macOS`, since Fleet EDR is a macOS-only product.

#### Scenario: Coverage when rules are registered

- **GIVEN** at least one detection rule registered with one or more ATT&CK techniques
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON whose `techniques` array contains an entry for every covered technique
- **AND** each entry identifies the rule ids that cover that technique

#### Scenario: Coverage with no rules

- **GIVEN** a server with no rules registered
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON with an empty `techniques` array rather than an error

#### Scenario: Layer is scoped to the macOS platform

- **GIVEN** a server serving the ATT&CK coverage layer
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the returned Navigator layer JSON carries `filters.platforms` equal to `["macOS"]`
- **AND** the upstream Navigator renders only the macOS matrix when the layer is imported

### Requirement: Per-rule documentation endpoint

The system SHALL expose `GET /api/rules` returning the per-rule documentation surface the admin UI's rule-detail page relies on. The response MUST include, for every registered rule, the rule's `id`, the list of ATT&CK `techniques` it covers, and a `doc` object carrying at least `title`, `summary`, `description`, `severity`, and `event_types`. When a rule declares false-positive sources or limitations, those MUST be exposed under `false_positives` and `limitations` respectively.

The "Rule with config knobs" scenario is dropped: per-rule config knobs (`doc.config`) are retired (rule tuning moved to the DB-backed detection-config surface in #459), so the endpoint no longer exposes a `config` array.

#### Scenario: Operator reads the rule catalog

- **GIVEN** a server with one or more rules registered
- **WHEN** the operator requests `GET /api/rules`
- **THEN** the server returns `200 OK` with a `rules` array
- **AND** each entry carries `id`, `techniques`, and a non-empty `doc` block with `title`, `summary`, `description`, `severity`, and `event_types`

### Requirement: Operator mutation endpoints reject oversize request bodies

Operator mutation endpoints that read a JSON request body MUST bound the read at a per-route byte cap and reject a body that exceeds the cap with `413 Request Entity Too Large` and a typed `*.body_too_large` error code, BEFORE attempting to decode it. The server MUST NOT silently truncate an oversize body (which would otherwise surface as a misleading `invalid_json` 400 or be accepted as a partial payload). A body at or below the cap is processed normally.

#### Scenario: Oversize application control mutation body is rejected

- **GIVEN** an authenticated operator POSTs an application-control mutation whose body exceeds the route's cap (16 KiB per-rule, 256 KiB bulk-upsert)
- **WHEN** the server reads the request body
- **THEN** the server returns `413` with `{"error": "application_control.body_too_large"}`
- **AND** the policy is not modified

#### Scenario: Oversize detection config mutation body is rejected

- **GIVEN** an authenticated operator POSTs a detection-config mutation whose body exceeds the 16 KiB cap
- **WHEN** the server reads the request body
- **THEN** the server returns `413` with `{"error": "detection_config.body_too_large"}`
- **AND** the detection-config state is not modified

### Requirement: Operator actions commit their audit entry

The audit entry for an operator issuing a command or withdrawing one SHALL be committed in the same transaction as the command row it records, so an audit reader can never find a command issued to a host without an entry naming who issued it. Because the audit store belongs to another bounded context and cannot join that transaction, the entry SHALL be committed to an outbox and delivered to the audit store afterwards. Delivery MAY lag the action, SHALL be retried until it succeeds, and SHALL NOT drop an entry. Delivery SHALL NOT be carried out by the action's own request: the request SHALL commit its entry, ask for delivery, and answer, so that an audit store that is slow or unavailable delays the row rather than the response to an action that has already been carried out. An operator whose request for a destructive action times out cannot tell it from one that failed, and a retry issues it twice. Delivery SHALL also be attempted periodically and independently of any request, so that an entry whose request ended before it was delivered, or one written by another replica, is still delivered. An action that is refused or rolled back SHALL leave no entry. The delivered row SHALL carry the acting principal, the address the request came from, the affected host, the command's type and id, and the trace of the request that made it. The address MAY be absent from a row delivered by a replica running a version that predates the field, since such a replica reads the entry without it; the row itself SHALL still be delivered.

Issuing a command and withdrawing one SHALL be recorded as distinct actions, `command.issue` and `command.cancel`, because the two rows otherwise name the same host, command type and command id and nothing would distinguish a command that was sent from one that was taken back.

One operator action SHALL name one host throughout. The host a command is authorized against, the host it is stored against, and the host its audit entry names SHALL be the same identifier, so the authorization decision and the action it permitted can be correlated. The system SHALL therefore resolve the identifier at the request boundary, before authorizing, rather than letting each step normalize its own copy.

#### Scenario: An issued command commits its audit entry

- **GIVEN** an operator issuing a command to a host
- **WHEN** the command is queued
- **THEN** a `command.issue` entry has committed with it, naming the actor, the address they acted from, the host, and the command's type and id

#### Scenario: A withdrawn command is audited as a withdrawal

- **GIVEN** an operator withdrawing a command no agent has picked up
- **WHEN** the withdrawal commits
- **THEN** a `command.cancel` entry has committed with it, naming the same host, command type and command id as the issuance did

#### Scenario: One action names one host

- **GIVEN** a request issuing a command whose host id carries surrounding whitespace
- **WHEN** the command is queued
- **THEN** the authorization decision, the stored command and the committed audit entry all name the same host

#### Scenario: A refused action commits no audit entry

- **GIVEN** an issuance the service refuses, or a withdrawal of a command an agent has already acknowledged
- **WHEN** the action is refused
- **THEN** no audit entry is left in the outbox and no command row changed

#### Scenario: A slow audit store does not delay the action

- **GIVEN** an audit store that has not answered a delivery already in progress
- **WHEN** an operator issues a command
- **THEN** the command is queued, its entry is committed, and the request answers without waiting for the store
- **AND** the entry is delivered once the store answers

#### Scenario: An entry no request asked about is still delivered

- **GIVEN** an entry committed by a request that ended before it was delivered, or by another replica
- **WHEN** no request asks for a delivery
- **THEN** the periodic delivery records the row and clears the entry

#### Scenario: A delivery failure delays the audit row

- **GIVEN** an audit store that is unavailable when a command is issued
- **WHEN** the command is issued
- **THEN** the command is queued and its entry stays in the outbox
- **AND** a later delivery, once the store is available, records the row and clears the entry

### Requirement: Watched-path replacements guard against lost updates

`PUT /api/v1/detection-config/watched-paths` SHALL accept an optional `expected_version`, the version the caller's edit started from. When it is present and the stored set is at any other version, the server SHALL refuse the replacement with status 409 and the error code `detection_config.conflict`, naming the current version, and SHALL store nothing, queue nothing, and audit nothing. The comparison SHALL be made under the same lock as the replacement, so two replacements naming the same version cannot both succeed. A request without `expected_version` SHALL replace whatever is stored.

#### Scenario: A replacement based on an outdated set is refused

- **GIVEN** a stored set at version 1
- **WHEN** a caller permitted `detection_config.write` submits a replacement naming `expected_version` 0
- **THEN** it is refused with 409 and `detection_config.conflict`, and the message names version 1
- **AND** the stored set is unchanged, and no command is queued and no change audited
- **AND** of two replacements submitted together naming `expected_version` 1, exactly one is stored

### Requirement: The watched-path set names who last changed it

The watched-path GET and PUT responses SHALL carry `updated_by_label`, the display label resolved from `updated_by` when the response is written (a user's email, a service account's name, or `system`). It SHALL be absent for the set no one has changed and when the principal cannot be resolved, in which case clients fall back to `updated_by`.

#### Scenario: The set names its last changer by label

- **GIVEN** a set last changed by a user, and a set last changed by a principal that has since been deleted
- **WHEN** a caller reads each set, and when a user replaces a set
- **THEN** the response names the user by email for the first read and for the replacement
- **AND** carries no label for the deleted principal or for the set no one has changed

### Requirement: Hosts that miss the watched-path push get the set

The server SHALL periodically queue the current watched-path set, as a `set_watched_paths` command carrying the same `{version, epoch, paths}` the push sends, for every host with an active enrollment whose latest `set_watched_paths` command does not already carry it. A host SHALL be sent the set when it has no such command, when that command carried a different version or epoch than the current set, when it was queued no later than the host's latest enrollment (both times read from the database clock, so skew between the server and the database cannot reorder them), when it expired or was cancelled, or when it failed at least six hours ago.

A pending, acknowledged, or completed command at the current version, queued since the host's latest enrollment, SHALL count as delivered, so a host that is offline is not sent a new copy every time the server checks. A failed command SHALL count as delivered for six hours before the set is queued again, so a host whose agent cannot run the command does not accumulate a failed command every check. A failed command with no recorded completion time SHALL count as delivered rather than being queued again immediately, since nothing says how long ago it failed and retrying on every check is what the six-hour wait exists to prevent.

While the set has never been changed, the server SHALL queue nothing.

#### Scenario: A failure with no completion time is not retried at once

- **GIVEN** a host whose latest command for the current set failed with no recorded completion time
- **WHEN** the server checks
- **THEN** the set is not queued for it again

#### Scenario: A host enrolled after a change gets the set

- **GIVEN** a watched-path set was changed while a host was not yet enrolled
- **WHEN** the host has enrolled and the server next checks
- **THEN** the current set is queued for that host, carrying the same version and epoch the push carried
- **AND** it is not queued again while that command is pending

#### Scenario: An expired or reinstalled host gets the set again

- **GIVEN** a host whose command for the current set expired undelivered, and a host that took the set and then enrolled again after a reinstall
- **WHEN** the server next checks
- **THEN** the current set is queued for both hosts

### Requirement: Watched file paths are configured over the API

The server SHALL hold one watched-path set: a version and a list of entries, each an absolute `path` and a `match` of `literal` or `prefix`, which every host's file-tamper client watches on top of its built-in paths. Version 0 SHALL be the empty set.

`GET /api/v1/detection-config/watched-paths` SHALL return the set, the built-in paths every host watches regardless of it, and the maximum number of entries, to a caller permitted `detection_config.read`.

`PUT /api/v1/detection-config/watched-paths` SHALL replace the set, for a caller permitted `detection_config.write`, only when the request carries a `paths` list (an empty list clears the set; a request without one is refused, so a misspelled field cannot remove every path), a non-blank reason, and a valid set. A replacement SHALL be stored as the next version, SHALL queue a `set_watched_paths` command carrying `{version, epoch, paths}` for every host with an active enrollment, and SHALL be audited with the reason, the set it replaced, the new set, and the number of hosts the command was queued for and missed. The counts are added after the replacement commits, so a push that outlasts its audit entry's bounded hold, or a server that stops before adding them, leaves the row without them, as the detection-config audit outbox requirement states. The audit entry SHALL be committed with the replacement, as for every detection-config change. A command that could not be queued for some hosts SHALL NOT fail the replacement, which is already stored; the response SHALL report both counts, and when the enrolled hosts could not be listed at all it SHALL say so rather than report an empty fleet.

`epoch` is the set's update time in Unix microseconds. Hosts order sets by epoch and then version, so each replacement SHALL receive both a version and an epoch later than the set it replaced, and concurrent replacements SHALL each audit the set they actually replaced.

The server is the only place the set is validated, so it SHALL refuse a proposed set, storing nothing and queueing nothing, when it has more than 32 entries, encodes to more than 8 KiB as the server writes it into the command (the fan-out repeats that payload on each row of a batched insert, which must stay inside a 4 MiB `max_allowed_packet`), or has any entry whose path is not absolute, has an empty, `.` or `..` segment, is longer than 1023 bytes in its `/private` spelling (the one the extension mutes for `/etc`, `/tmp` and `/var`; `PATH_MAX` less the C string's terminating NUL), or contains an ASCII control character (NUL included), whose `match` is neither `literal` nor `prefix`, that is a `literal` ending in `/`, that is a `prefix` not ending in `/`, that is a `prefix` naming a top-level directory, or that repeats another entry. A path under `/private/etc`, `/private/tmp`, or `/private/var` SHALL be judged by its root-linked form, both for the top-level rule and for repetition. The refusal SHALL name the entry and the reason.

A top-level prefix is refused because its cost is not bounded by the set's size: every write under a tree such as `/Users/` would reach the wire.

#### Scenario: An operator reads the watched-path set

- **GIVEN** a caller permitted `detection_config.read`
- **WHEN** they request the watched-path set
- **THEN** the response carries the version, the entries, the built-in paths, and the maximum number of entries

#### Scenario: An operator replaces the watched-path set with a reason

- **GIVEN** a caller permitted `detection_config.write` and three enrolled hosts
- **WHEN** they replace the set with a valid list of entries and a reason
- **THEN** the set is stored as the next version with those entries
- **AND** a `set_watched_paths` command carrying that version, the set's update time as its epoch, and those entries is queued for each of the three hosts
- **AND** the version and the epoch are both later than those of the set it replaced
- **AND** the change is audited with the reason, the previous and new sets, and the host counts

#### Scenario: A set the server would not watch is refused

- **GIVEN** a proposed set with an entry the rules above refuse
- **WHEN** a caller permitted `detection_config.write` submits it with a reason
- **THEN** the request is refused with a message naming the entry and why
- **AND** the stored set is unchanged and no command is queued

#### Scenario: A change without a list is refused

- **GIVEN** a stored set with entries
- **WHEN** a caller permitted `detection_config.write` submits a replacement with a reason but no `paths` list
- **THEN** the request is refused, the stored set is unchanged, and no command is queued

#### Scenario: A change without a reason is refused

- **GIVEN** a caller permitted `detection_config.write`
- **WHEN** they submit a valid set with a blank reason
- **THEN** the request is refused, the stored set is unchanged, and no command is queued

#### Scenario: Reading and changing the set need their permissions

- **GIVEN** a caller not permitted `detection_config.read`, and one permitted to read but not `detection_config.write`
- **WHEN** the first requests the set and the second submits a replacement
- **THEN** both are refused as forbidden, and the stored set is unchanged

#### Scenario: A push that misses hosts does not undo the change

- **GIVEN** a valid replacement whose commands cannot be queued for the enrolled hosts
- **WHEN** a caller permitted `detection_config.write` submits it with a reason
- **THEN** the set is stored as the next version
- **AND** the response and the audit row report how many hosts the command was not queued for
- **AND** when the enrolled hosts could not be listed, they say the push was skipped for that reason rather than reporting no hosts
