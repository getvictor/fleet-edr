## ADDED Requirements

### Requirement: Authentication outcomes write an audit row

The system SHALL record an audit row for every authentication outcome, success or
failure, regardless of authentication method. Action names MUST follow the pattern
`auth.<flow>.<outcome>` where `<flow>` is one of `oidc` or `breakglass` (named after
the *flow* that produced the outcome, not the credential type - the break-glass flow
combines a local password and a WebAuthn assertion under a single `breakglass` flow
so dashboards stay cohesive). The action name MUST be one of `auth.oidc.success`,
`auth.oidc.failure`, `auth.oidc.callback.error`, `auth.breakglass.success`, or
`auth.breakglass.failure`. The row MUST include the request timestamp, the source IP,
the user agent, the request id, the action name, the decision (`allow`, `deny`, or
`error`), the reason, and (when known) the actor user id and identity id. Audit row
writes MUST NOT block on the user response: a write failure SHALL be logged at ERROR
and counted as a metric but the user request continues.

#### Scenario: Successful SSO login is audited

- **GIVEN** a successful Okta OIDC callback that mints a session
- **WHEN** the response is sent
- **THEN** an audit row exists with `action='auth.oidc.success'`, `decision='allow'`,
  the actor's user id and identity id, and the request id

#### Scenario: Failed break-glass login is audited without leaking the failure mode to the client

- **GIVEN** a break-glass login attempt with a wrong password
- **WHEN** the server validates the submission
- **THEN** the client receives a generic invalid-credentials response
- **AND** the audit row records `action='auth.breakglass.failure'` and the precise
  failure reason in the row's `reason` field (e.g. `password_mismatch`,
  `webauthn_assertion_invalid`)

#### Scenario: Audit write failure does not fail the user request

- **GIVEN** a transient database failure when inserting the audit row for a successful
  login
- **WHEN** the recorder attempts the insert
- **THEN** the user request still completes successfully (the session is still minted)
- **AND** the failure is logged at ERROR with a unique structured key
- **AND** the `edr_audit_write_failures_total` metric is incremented

### Requirement: Authorization decisions on state-changing actions write an audit row

The system SHALL record an audit row for every authorization decision on a
state-changing action, including allow, deny, and error outcomes. Read-only actions
SHALL be sampled at a configurable fraction (`audit.read_sampling`, default `0.0` in
wave 1). When the actor is a break-glass account, the read-sampling fraction MUST be
treated as `1.0` regardless of configuration so every break-glass action is auditable
end-to-end.

#### Scenario: State-changing allow is recorded

- **GIVEN** an authorization decision of `allow` on a state-changing action (for
  example, host isolate)
- **WHEN** the chokepoint records the decision
- **THEN** an audit row exists with `decision='allow'`, the action name, the resource
  type and id, and the actor

#### Scenario: Read sampling defaults skip non-break-glass reads

- **GIVEN** `audit.read_sampling = 0.0` and a non-break-glass actor
- **WHEN** the chokepoint records an allow decision on a read action
- **THEN** no audit row is written

#### Scenario: Break-glass reads are always recorded

- **GIVEN** `audit.read_sampling = 0.0` and a break-glass actor
- **WHEN** the chokepoint records an allow decision on a read action
- **THEN** an audit row IS written despite the sampling configuration

### Requirement: Audit rows are dual-emitted to slog and OTel

The system SHALL emit a structured slog record and OTel span attributes for every
audit row it inserts. The slog record MUST be at INFO when the decision is `allow`,
WARN when the decision is `deny`, the action is a break-glass action, or the decision
is `error`. The OTel span attributes MUST be set on the active request span and MUST
include `edr.audit.action`, `edr.audit.decision`, and `edr.audit.reason`. The dual
emit MUST happen even when the database insert fails so the observability pipeline
sees a record.

#### Scenario: Allow emits INFO

- **GIVEN** an authorization allow on a state-changing action
- **WHEN** the recorder emits
- **THEN** a structured slog record at INFO is written with the audit fields
- **AND** the active request span carries the three `edr.audit.*` attributes

#### Scenario: Deny emits WARN

- **GIVEN** an authorization deny on any action
- **WHEN** the recorder emits
- **THEN** a structured slog record at WARN is written with the audit fields

### Requirement: Append-only persistence

The system SHALL treat the audit table as append-only at the application layer: no
production code path SHALL update or delete an existing audit row. Operator-driven
retention pruning MAY happen via a documented out-of-band procedure but MUST NOT be
exposed in the admin API in wave 1. The schema SHALL be designed so a future
dual-database-user setup can revoke `UPDATE` and `DELETE` privileges on the audit
table without code changes.

#### Scenario: No code path updates an audit row

- **GIVEN** any production code path that interacts with the audit recorder
- **WHEN** static analysis (a build-time check) inspects the call sites
- **THEN** no `UPDATE audit_events` or `DELETE FROM audit_events` statement is reachable
  from production code

### Requirement: Audit-log read endpoint requires `audit.read` and audits its own access

The system SHALL expose `GET /api/audit-events` returning audit rows in reverse-chronological
order with paging. The endpoint MUST require an authorization decision of `allow` for
the action `audit.read`. Every successful read of the audit log MUST itself record an
audit row (`action='audit.read'`) so a future reviewer can reconstruct who inspected the
audit trail and when.

#### Scenario: Auditor reads the audit log

- **GIVEN** an authenticated session bound to the `auditor` role
- **WHEN** the operator issues `GET /api/audit-events?limit=50`
- **THEN** the server returns `200 OK` with up to 50 rows in reverse-chronological order
- **AND** the read itself produces an audit row with `action='audit.read'` and the
  query parameters in the row's payload

#### Scenario: Analyst is denied the audit log

- **GIVEN** an authenticated session bound only to the `analyst` role
- **WHEN** the operator issues `GET /api/audit-events`
- **THEN** the server returns `403 Forbidden`
- **AND** an audit row is recorded with decision `deny` and reason
  `no_role_grants_action`
