# Server Admin Surface Specification

## Purpose

The server admin surface is the operator's API into the Fleet EDR control plane. It exposes the endpoints the admin UI and any
externally scripted tooling rely on: enumerating enrolled hosts, revoking a host's credentials, reading and mutating the
application-control policies + rules that fan out to enrolled hosts, and rendering the detection content (per-rule documentation
and ATT&CK technique coverage) that buyers and SOC analysts compare against. It is the only documented way for a human operator
to change runtime state on the server.

This specification fixes the HTTP contract: paths, methods, request and response shapes, auth boundary, and the audit trail every
state-changing call leaves behind, so the UI, integration scripts, and post-incident reviewers can reason about admin behaviour
without reading the handler source.

## Requirements

### Requirement: Authenticated admin boundary

The server MUST gate every endpoint defined by this capability (`/api/enrollments`,
`/api/enrollments/{host_id}/revoke`, every route under the `/api/v1/app-control/*` prefix including the
`policies`, `policies/{id}/rules`, `policies/{id}/rules:bulkUpsert`, `rules`, `host-groups`, and
`policies/{id}/assignments` sub-paths for all HTTP methods, `/api/attack-coverage`, and `/api/rules`) behind the
operator-session middleware, so a caller that is not authenticated as an operator SHALL receive `401 Unauthorized`.
These endpoints share an authentication boundary with the rest of the operator API; there is no separate "admin"
auth mode in the current implementation. The host-groups and assignments sub-resources are present on the wire but
their CRUD contracts are not specified in this document; they inherit the auth boundary above.

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

The system SHALL expose `GET /api/enrollments` returning the set of enrolled hosts known to the server. Each entry MUST
identify the host and carry the metadata needed for the admin host list (host id, hostname, agent version, OS version, last-seen
timestamp, enrollment status).

#### Scenario: Operator lists enrolled hosts

- **GIVEN** at least one host has enrolled successfully
- **WHEN** the operator requests `GET /api/enrollments`
- **THEN** the server returns `200 OK` with a JSON array of enrollment rows
- **AND** every row includes the host id and the host's last-seen timestamp

### Requirement: Revoke a host enrollment

The system SHALL expose `POST /api/enrollments/{host_id}/revoke` to invalidate a host's bearer token immediately. The
request body MUST carry an operator-supplied `reason` and `actor`; the server MUST reject the request when either is empty. Once
revoked, the next authenticated request from that host's agent MUST receive `401 Unauthorized`.

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

The system SHALL expose `GET /api/v1/app-control/policies` returning the list of application-control policies known to the
server. The list response MUST NOT inline the `rules` field for each policy (it is omitted from the list shape to keep the
index endpoint cheap); each entry carries the policy's `id`, `name`, `description`, `version`, and `created_at` /
`updated_at` audit timestamps plus an assignment count. The system SHALL also expose
`GET /api/v1/app-control/policies/{id}` returning a single policy by id with its `rules` array inlined. The seed pass
creates a default policy on first boot; reading the list before any operator change MUST surface that default policy.

#### Scenario: First-query returns the seeded default policy

- **GIVEN** a server that has never had an operator-driven policy mutation
- **WHEN** the operator requests `GET /api/v1/app-control/policies`
- **THEN** the server returns `200 OK`
- **AND** the response includes the seeded default policy with its `id`, `name`, and `version` set

#### Scenario: Read after operator changes

- **GIVEN** the operator has previously created at least one application-control rule on a policy
- **WHEN** the operator requests `GET /api/v1/app-control/policies/{id}` for that policy
- **THEN** the response carries the latest persisted `version` and inlines the policy's `rules` array with the operator's
  changes reflected

### Requirement: Persist and fan out application-control rules

The system SHALL expose `POST /api/v1/app-control/policies/{id}/rules`, `PATCH /api/v1/app-control/rules/{id}`, and
`DELETE /api/v1/app-control/rules/{id}` that atomically apply the requested mutation and bump the owning policy's
`version`. The system SHALL attempt to queue a `set_application_control` command carrying the post-bump policy state
for every active host assigned to the policy, on a best-effort basis. A failure to enqueue the command for an individual
host MUST NOT roll back the rule mutation; the server MUST log the per-host fan-out failures so the next agent poll or
admin push can reconcile, and MUST record the fan-out count in the audit payload.

Every mutation request body MUST carry a non-empty `reason`. The operator identity (`actor`) is NOT carried in the body;
it is derived from the authenticated session context and recorded in the audit row in the form `user:<id>`. The
POST (create) body MUST additionally carry `rule_type` and `identifier`; PATCH and DELETE accept partial mutations against
the existing rule and do not need either. `rule_type` MUST be one of the supported uppercase tokens (`BINARY`, `CDHASH`,
`SIGNINGID`, `TEAMID`; `CERTIFICATE` and `PATH` exist on the wire enum but are not yet enforced and currently surface
as an unsupported-rule-type error). `identifier` MUST satisfy the format rules for the declared `rule_type`:

- `BINARY`: 64 lowercase hex characters (SHA-256 of the executable file).
- `CDHASH`: 40 lowercase hex characters (Code Directory hash).
- `SIGNINGID`: `<TeamID>:<bundle.id>` or `platform:<bundle.id>` for Apple platform binaries.
- `TEAMID`: 10-character alphanumeric Apple Developer Team ID (e.g. `EQHXZ8M8AV`).

A request that violates the rule-type or identifier constraints MUST be rejected with `400 Bad Request` and the policy
MUST NOT be modified.

#### Scenario: Valid rule create increments version and fans out

- **GIVEN** a current policy at version `v`
- **WHEN** the operator POSTs a valid rule with a non-empty `reason`
- **THEN** the server returns `201 Created` carrying the new rule
- **AND** the owning policy's `version` has bumped to `v+1` (observable via a subsequent `GET /api/v1/app-control/policies/{id}`)
- **AND** the server attempts to queue a `set_application_control` command for every active host assigned to the policy
- **AND** any host whose enqueue fails is logged so a subsequent reconcile can resend

#### Scenario: Invalid identifier is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator POSTs a rule whose `identifier` violates the format rules for the declared `rule_type` (e.g., a
  non-hex string for `rule_type=BINARY`, or a string longer than 10 characters for `rule_type=TEAMID`)
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Unsupported rule type is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator POSTs a rule whose `rule_type` is not in the supported set (e.g., `CERTIFICATE` or `PATH` in the
  current cut, both of which exist on the enum but lack validators)
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Missing actor or reason is rejected

- **GIVEN** an authenticated operator
- **WHEN** a rule mutation reaches the store layer with either an empty `reason` (which the HTTP handler forwards from
  the request body) or an empty server-supplied `actor` identifier (a session-middleware bug)
- **THEN** the store returns `ErrAppControlInvalidRequest`, which the HTTP handler maps to `400 Bad Request`, and the
  policy MUST NOT be modified

### Requirement: Audit trail for state-changing admin actions

Every successful state-changing admin call defined by this specification (revoke, and application-control rule create / update /
delete) SHALL emit a structured audit log record carrying at minimum a timestamp, the operator's identity (`actor`, sourced from
the session context as `user:<id>` for application-control mutations), the operator-supplied `reason` from the request body, the
action name, and either the affected host id (for revoke) or the affected rule id + post-bump policy version + fan-out count
(for application-control rule mutations). The audit record MUST be emitted at a level that downstream SIEM and SigNoz queries
can filter on so SOC teams can reconstruct who changed what and when. The implementation also emits audit rows for policy CRUD
endpoints exposed under `/api/v1/app-control/policies` (create, update, delete); those flows are not specified in this document.

#### Scenario: Revoke produces an audit record

- **GIVEN** an operator who successfully revokes a host
- **WHEN** the revoke completes
- **THEN** a structured log record is emitted carrying the operator's `actor`, the operator's `reason`, the host id, and the action
  identifier `revoke`

#### Scenario: Rule update produces an audit record

- **GIVEN** an operator who successfully PATCHes an existing application-control rule
- **WHEN** the update commits and the fan-out completes
- **THEN** a structured audit record is emitted carrying the operator's `actor`, the operator's `reason`, the affected rule id,
  the post-bump policy version, and the count of active hosts the `set_application_control` command was fanned out to

### Requirement: ATT&CK coverage layer endpoint

The system SHALL expose `GET /api/attack-coverage` returning a MITRE ATT&CK Navigator layer JSON document that enumerates
the techniques covered by the registered detection rules. The document MUST be importable directly into the upstream MITRE
ATT&CK Navigator. Each covered technique MUST identify the rule (or rules) that cover it.

#### Scenario: Coverage when rules are registered

- **GIVEN** at least one detection rule registered with one or more ATT&CK techniques
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON whose `techniques` array contains an entry for every covered technique
- **AND** each entry identifies the rule ids that cover that technique

#### Scenario: Coverage with no rules

- **GIVEN** a server with no rules registered
- **WHEN** the operator requests `GET /api/attack-coverage`
- **THEN** the server returns a Navigator layer JSON with an empty `techniques` array rather than an error

### Requirement: Per-rule documentation endpoint

The system SHALL expose `GET /api/rules` returning the per-rule documentation surface the admin UI's rule-detail page
relies on. The response MUST include, for every registered rule, the rule's `id`, the list of ATT&CK `techniques` it covers, and
a `doc` object carrying at least `title`, `summary`, `description`, `severity`, and `event_types`. When a rule declares operator-
tunable knobs, false-positive sources, or limitations, those MUST be exposed under `config`, `false_positives`, and `limitations`
respectively.

#### Scenario: Operator reads the rule catalog

- **GIVEN** a server with one or more rules registered
- **WHEN** the operator requests `GET /api/rules`
- **THEN** the server returns `200 OK` with a `rules` array
- **AND** each entry carries `id`, `techniques`, and a non-empty `doc` block with `title`, `summary`, `description`, `severity`,
  and `event_types`

#### Scenario: Rule with config knobs

- **GIVEN** a registered rule that declares one or more configuration knobs
- **WHEN** the operator reads the rule catalog
- **THEN** that rule's `doc.config` lists every knob with `env_var`, `type`, `default`, and `description`
