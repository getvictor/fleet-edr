# Server Admin Surface Specification

## Purpose

The server admin surface is the operator's API into the Fleet EDR control plane. It exposes the endpoints the admin UI and any
externally scripted tooling rely on: enumerating enrolled hosts, revoking a host's credentials, viewing and pushing the
server-driven blocklist policy, and rendering the detection content (per-rule documentation and ATT&CK technique coverage) that
buyers and SOC analysts compare against. It is the only documented way for a human operator to change runtime state on the
server.

This specification fixes the HTTP contract — paths, methods, request and response shapes, auth boundary, and the audit trail every
state-changing call leaves behind — so the UI, integration scripts, and post-incident reviewers can reason about admin behaviour
without reading the handler source.

## Requirements

### Requirement: Authenticated admin boundary

Every admin endpoint SHALL require a caller authenticated as an admin user. The server MUST gate all `/api/v1/admin/*` routes
behind admin authentication middleware so that an unauthenticated or non-admin caller receives `401 Unauthorized`.

#### Scenario: Unauthenticated request is rejected

- **GIVEN** a client that has not authenticated
- **WHEN** the client requests any `/api/v1/admin/*` endpoint
- **THEN** the server returns `401 Unauthorized`
- **AND** the response body uses the standard error shape `{"error": "..."}`

#### Scenario: Authenticated admin request proceeds

- **GIVEN** a client holding a valid admin session cookie
- **WHEN** the client requests an admin endpoint and satisfies any required CSRF check for the HTTP method
- **THEN** the request is dispatched to the corresponding admin handler

### Requirement: List enrollments

The system SHALL expose `GET /api/v1/admin/enrollments` returning the set of enrolled hosts known to the server. Each entry MUST
identify the host and carry the metadata needed for the admin host list (host id, hostname, agent version, OS version, last-seen
timestamp, enrollment status).

#### Scenario: Operator lists enrolled hosts

- **GIVEN** at least one host has enrolled successfully
- **WHEN** the operator requests `GET /api/v1/admin/enrollments`
- **THEN** the server returns `200 OK` with a JSON array of enrollment rows
- **AND** every row includes the host id and the host's last-seen timestamp

### Requirement: Revoke a host enrollment

The system SHALL expose `POST /api/v1/admin/enrollments/{host_id}/revoke` to invalidate a host's bearer token immediately. The
request body MUST carry an operator-supplied `reason` and `actor`; the server MUST reject the request when either is empty. Once
revoked, the next authenticated request from that host's agent MUST receive `401 Unauthorized`.

#### Scenario: Revoke a known host

- **GIVEN** a host with a currently valid enrollment
- **WHEN** the operator POSTs to `/api/v1/admin/enrollments/{host_id}/revoke` with a non-empty `reason` and `actor`
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

### Requirement: Read the current blocklist policy

The system SHALL expose `GET /api/v1/admin/policy` returning the current default policy. The response MUST always include a
`name`, a monotonically increasing `version`, a `blocklist` object with `paths` and `hashes` arrays, plus `updated_at` and
`updated_by` audit fields. On a freshly-seeded server with no operator changes the policy MUST return cleanly with empty `paths`
and `hashes`.

#### Scenario: First-query returns the seeded empty policy

- **GIVEN** a server that has never had a policy push
- **WHEN** the operator requests `GET /api/v1/admin/policy`
- **THEN** the server returns `200 OK`
- **AND** the response body's `blocklist.paths` and `blocklist.hashes` are present and empty

#### Scenario: Read after operator changes

- **GIVEN** the operator has previously persisted a non-empty blocklist
- **WHEN** the operator requests `GET /api/v1/admin/policy`
- **THEN** the response carries the latest persisted version, blocklist contents, and updated-by attribution

### Requirement: Persist and fan out a new blocklist policy

The system SHALL expose `PUT /api/v1/admin/policy` that atomically bumps the policy's version and replaces the blocklist.
The system SHALL attempt to queue a `set_blocklist` command carrying the new version for every active host on a
best-effort basis. A failure to enqueue the command for an individual host MUST NOT roll back the policy update; the
server MUST log the per-host fan-out failures so the next agent poll or admin push can reconcile, and MAY surface
per-host fan-out diagnostics in the response. The request body MUST carry `actor` and `reason` (both required), plus
optional `paths` and `hashes` arrays. Paths MUST be absolute (start with `/`); hashes MUST be 64-character lowercase hex
(SHA-256). A request that violates either constraint MUST be rejected with `400 Bad Request` and the policy MUST NOT be
modified.

#### Scenario: Valid policy push increments version and fans out

- **GIVEN** a current policy at version `v`
- **WHEN** the operator PUTs a valid policy with non-empty `actor` and `reason`
- **THEN** the server returns `200 OK` carrying the new policy at version `v+1`
- **AND** the server attempts to queue a `set_blocklist` command for every active host carrying the new version and
  blocklist
- **AND** any host whose enqueue fails is logged so a subsequent reconcile can resend

#### Scenario: Invalid path is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator PUTs a policy whose `paths` includes a non-absolute entry such as `tmp/payload`
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Invalid hash is rejected without persisting

- **GIVEN** any current policy
- **WHEN** the operator PUTs a policy whose `hashes` includes anything other than 64 lowercase hex characters
- **THEN** the server returns `400 Bad Request`
- **AND** the persisted policy is unchanged

#### Scenario: Missing actor or reason is rejected

- **GIVEN** an authenticated operator
- **WHEN** the operator PUTs a policy body without `actor` or without `reason`
- **THEN** the server returns `400 Bad Request` and does not modify the policy

### Requirement: Audit trail for state-changing admin actions

Every successful state-changing admin call (revoke, policy update) SHALL emit a structured audit log record carrying at minimum a
timestamp, the operator-supplied `actor`, the operator-supplied `reason`, the action name, and the affected host id (for revoke)
or new policy version and per-list change counts (for policy update). The audit record MUST be emitted at a level that downstream
SIEM and SigNoz queries can filter on so SOC teams can reconstruct who changed what and when.

#### Scenario: Revoke produces an audit record

- **GIVEN** an operator who successfully revokes a host
- **WHEN** the revoke completes
- **THEN** a structured log record is emitted carrying the operator's `actor`, the operator's `reason`, the host id, and the action
  identifier `revoke`

#### Scenario: Policy update produces an audit record

- **GIVEN** an operator who successfully PUTs a new policy
- **WHEN** the update commits
- **THEN** a structured log record is emitted carrying the operator's `actor`, the operator's `reason`, the new version, and the
  count of active hosts the new policy was fanned out to

### Requirement: ATT&CK coverage layer endpoint

The system SHALL expose `GET /api/v1/admin/attack-coverage` returning a MITRE ATT&CK Navigator layer JSON document that enumerates
the techniques covered by the registered detection rules. The document MUST be importable directly into the upstream MITRE
ATT&CK Navigator. Each covered technique MUST identify the rule (or rules) that cover it.

#### Scenario: Coverage when rules are registered

- **GIVEN** at least one detection rule registered with one or more ATT&CK techniques
- **WHEN** the operator requests `GET /api/v1/admin/attack-coverage`
- **THEN** the server returns a Navigator layer JSON whose `techniques` array contains an entry for every covered technique
- **AND** each entry identifies the rule ids that cover that technique

#### Scenario: Coverage with no rules

- **GIVEN** a server with no rules registered
- **WHEN** the operator requests `GET /api/v1/admin/attack-coverage`
- **THEN** the server returns a Navigator layer JSON with an empty `techniques` array rather than an error

### Requirement: Per-rule documentation endpoint

The system SHALL expose `GET /api/v1/admin/rules` returning the per-rule documentation surface the admin UI's rule-detail page
relies on. The response MUST include, for every registered rule, the rule's `id`, the list of ATT&CK `techniques` it covers, and
a `doc` object carrying at least `title`, `summary`, `description`, `severity`, and `event_types`. When a rule declares operator-
tunable knobs, false-positive sources, or limitations, those MUST be exposed under `config`, `false_positives`, and `limitations`
respectively.

#### Scenario: Operator reads the rule catalog

- **GIVEN** a server with one or more rules registered
- **WHEN** the operator requests `GET /api/v1/admin/rules`
- **THEN** the server returns `200 OK` with a `rules` array
- **AND** each entry carries `id`, `techniques`, and a non-empty `doc` block with `title`, `summary`, `description`, `severity`,
  and `event_types`

#### Scenario: Rule with config knobs

- **GIVEN** a registered rule that declares one or more configuration knobs
- **WHEN** the operator reads the rule catalog
- **THEN** that rule's `doc.config` lists every knob with `env_var`, `type`, `default`, and `description`
