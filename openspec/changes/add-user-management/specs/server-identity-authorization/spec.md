## ADDED Requirements

### Requirement: Every privileged action funnels through one authorization chokepoint

The system SHALL evaluate every privileged action through a single authorization
chokepoint that takes the calling actor (derived from the session), the action name,
and the target resource and returns a decision (allow or deny) plus a machine-readable
reason. No privileged handler MAY make its own role check; the chokepoint is the only
sanctioned place where a permission decision is made. Action names MUST come from a
registered enumeration; a request whose action is not registered SHALL be denied with
reason `action_not_registered` (defense-in-depth against typos and ghost permissions).

#### Scenario: Authorized action is allowed and recorded

- **GIVEN** an authenticated actor whose role grants the requested action at the
  resource's scope
- **WHEN** the chokepoint evaluates the request
- **THEN** the response is `{allow: true, reason: "granted"}`
- **AND** an audit row is recorded with decision `allow`

#### Scenario: Unauthorized action is denied with a reason

- **GIVEN** an authenticated actor whose roles do not grant the requested action at the
  resource's scope
- **WHEN** the chokepoint evaluates the request
- **THEN** the response is `{allow: false, reason: <policy-supplied reason>}`
- **AND** the calling handler returns `403 Forbidden` to the client
- **AND** an audit row is recorded with decision `deny` and the same reason

#### Scenario: Unregistered action is denied as defense in depth

- **GIVEN** a handler that calls the chokepoint with an action name not present in the
  registered enumeration
- **WHEN** the chokepoint evaluates the request
- **THEN** the decision is `{allow: false, reason: "action_not_registered"}`
- **AND** the build fails CI by way of a parity check between the action enumeration
  and the policy bundle, so the production binary cannot ship with this state

### Requirement: Five seeded roles bundle permissions for the deployment

The system SHALL seed five roles at startup and SHALL keep their `is_builtin` flag set
so they cannot be deleted via the admin API: `super_admin` (tenant + SSO config + every
permission below), `admin` (day-to-day administration: user.read, user.invite, policy.*,
host.*, alert.*), `senior_analyst` (investigate + take destructive action: host.read,
host.isolate, host.kill_process, alert.*), `analyst` (investigate + comment + escalate:
host.read, process.read, alert.read, alert.comment), and `auditor` (read-only including
audit.read). The break-glass user MUST be bound to `super_admin` at tenant scope.
SSO-provisioned users MUST default to `analyst` at tenant scope; the system MUST NOT
auto-elevate any role from a SSO claim.

#### Scenario: Roles are seeded on first boot

- **GIVEN** an empty `roles` table
- **WHEN** the server boots
- **THEN** exactly the five seeded roles exist with `is_builtin=1`
- **AND** the break-glass user (when present) is bound to `super_admin` at tenant scope

#### Scenario: Built-in role cannot be deleted

- **GIVEN** an authenticated `super_admin`
- **WHEN** the operator attempts to delete a role with `is_builtin=1`
- **THEN** the server returns a typed error and does not modify the role

### Requirement: Role bindings carry a tenant + scope so future scoping is non-breaking

Every role binding SHALL carry a `tenant_id`, a `scope_type` from the set
`{'tenant', 'host_group', 'host'}`, and a `scope_id`. Wave 1 SHALL enforce only
`scope_type='tenant'` (with `scope_id='*'`); a binding with a non-tenant scope_type
MUST be persisted but MUST NOT be honored by the chokepoint until the corresponding
scope resolver ships. A binding MAY carry an `expires_at`; an expired binding MUST be
treated as if it did not exist when the chokepoint evaluates a request.

#### Scenario: Tenant-scoped binding grants the action

- **GIVEN** a role binding with `scope_type='tenant'`, `scope_id='*'`, and the role
  granting the requested action
- **WHEN** the chokepoint evaluates a request whose resource lives in the same tenant
- **THEN** the decision is `{allow: true, reason: "granted"}`

#### Scenario: Host-scoped binding does not grant the action in wave 1

- **GIVEN** a role binding with `scope_type='host'` and `scope_id` matching the
  resource host id
- **WHEN** the chokepoint evaluates a request that would only be authorized via the
  host scope
- **THEN** the decision is `{allow: false, reason: "scope_not_yet_supported"}`
- **AND** the audit row records the deny decision so the operator can see scopes are
  not yet honored

#### Scenario: Expired binding is ignored

- **GIVEN** a role binding whose `expires_at` is in the past
- **WHEN** the chokepoint loads the actor's bindings
- **THEN** the expired binding is not part of the evaluation input
- **AND** if no other binding grants the action, the decision is deny

### Requirement: Tenant scaffolding column on every long-lived table

Every table that belongs to a tenant in the long run SHALL carry a `tenant_id`
column whose default value is the literal string `'default'`. Wave 1 MUST seed exactly
one tenant (`id='default'`, `status='active'`) and MUST NOT use the column as a query
filter. The column SHALL be present at minimum on every identity-context table
(`users`, `sessions`, `roles`, `role_bindings`, `audit_events`) and on every
non-identity table whose rows logically belong to a tenant in wave 2's MSSP shape:
`hosts`, `alerts`, `policies`, `commands`, `enrollments`. The system MUST NOT enforce
foreign keys between `tenants` and any non-identity table.

#### Scenario: Default tenant exists at first boot

- **GIVEN** a fresh deployment
- **WHEN** the server boots
- **THEN** the `tenants` table contains exactly one row with `id='default'` and
  `status='active'`

#### Scenario: New row inherits the default tenant

- **GIVEN** a write to any tenant-scoped table that does not specify `tenant_id`
- **WHEN** the row is inserted
- **THEN** the row's `tenant_id` is `'default'`

#### Scenario: Wave 1 does not query on tenant_id

- **GIVEN** any read endpoint defined by an existing capability
- **WHEN** the server processes the read
- **THEN** the SQL filter does not include `tenant_id` (verified by query-builder
  inspection in tests; the column is purely scaffolding)

### Requirement: Authorization decisions sub-millisecond at p99

The system SHALL evaluate the authorization chokepoint at p99 latency under 1
millisecond on the deployment's production hardware. The benchmark harness MUST run on
every authorization-touching pull request, and a regression that pushes p99 above
1 ms SHALL fail the build. The benchmark MUST cover allow and deny paths and MUST use
the seeded roles plus a representative role-binding fan-out.

#### Scenario: Benchmark passes on the merge candidate

- **GIVEN** a pull request that touches the authorization engine, the policy bundle, or
  the action registry
- **WHEN** continuous integration runs the authorization benchmark
- **THEN** the recorded p99 over the standard input set is below 1 millisecond
- **AND** the build passes

#### Scenario: Benchmark regression blocks the build

- **GIVEN** a pull request whose change pushes the benchmark p99 above 1 millisecond
- **WHEN** continuous integration runs the benchmark
- **THEN** the build fails and the PR cannot be merged until the regression is
  addressed

### Requirement: Shadow mode rolls authorization out without enforcing

The system SHALL expose a configuration flag (`authz.shadow_mode`) that, when enabled,
makes the chokepoint always return `{allow: true, reason: "shadow_mode"}` while still
recording the would-be decision in the audit log. The flag MUST exist for the duration
of the wave-1 rollout and MUST be removable in a follow-up change once enforcement is
the steady state. The default for a fresh deployment SHALL be `shadow_mode=false`; an
upgrade path MAY default it to `true` for a deployment whose policy verdict has not yet
been validated against its handler set.

#### Scenario: Shadow mode allows but logs the would-be decision

- **GIVEN** `authz.shadow_mode=true` and a request whose policy decision would be deny
- **WHEN** the chokepoint evaluates the request
- **THEN** the response to the handler is `{allow: true, reason: "shadow_mode"}`
- **AND** an audit row is recorded with decision `deny` and the policy-supplied reason
- **AND** the audit row's payload notes that shadow mode was in effect so dashboards
  can distinguish would-be denies from real denies
