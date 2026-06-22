# Server Identity Authorization Specification

## Purpose

Authorization is the operator-side permission boundary for every privileged action the admin API exposes. A single chokepoint evaluates the calling actor (derived from the session), the action, and the target resource against a set of seeded roles and their bindings, returning an allow/deny decision with a machine-readable reason. Centralizing the decision in one place keeps permission logic out of individual handlers, makes every decision auditable against one policy, and lets future host-group / host scoping grow in without reworking call sites. The decision path is on every privileged request, so it carries a hard latency budget.

## Requirements

### Requirement: Every privileged action funnels through one authorization chokepoint

The system SHALL evaluate every privileged action through a single authorization chokepoint that takes the calling actor (derived from the session), the action name, and the target resource and returns a decision (allow or deny) plus a machine-readable reason. No privileged handler MAY make its own role check; the chokepoint is the only sanctioned place where a permission decision is made. Action names MUST come from a registered enumeration; a request whose action is not registered SHALL be denied with reason `action_not_registered` (defense-in-depth against typos and ghost permissions).

#### Scenario: Authorized action is allowed and recorded

- **GIVEN** an authenticated actor whose role grants the requested action at the resource's scope
- **WHEN** the chokepoint evaluates the request
- **THEN** the response is `{allow: true, reason: "granted"}`
- **AND** an audit row is recorded with decision `allow`

#### Scenario: Unauthorized action is denied with a reason

- **GIVEN** an authenticated actor whose roles do not grant the requested action at the resource's scope
- **WHEN** the chokepoint evaluates the request
- **THEN** the response is `{allow: false, reason: <policy-supplied reason>}`
- **AND** the calling handler returns `403 Forbidden` to the client
- **AND** an audit row is recorded with decision `deny` and the same reason

#### Scenario: Unregistered action is denied as defense in depth

- **GIVEN** a handler that calls the chokepoint with an action name not present in the registered enumeration
- **WHEN** the chokepoint evaluates the request
- **THEN** the decision is `{allow: false, reason: "action_not_registered"}`
- **AND** the build fails CI by way of a parity check between the action enumeration and the policy bundle, so the production binary cannot ship with this state

### Requirement: Five seeded roles bundle permissions for the deployment

The system SHALL seed five roles at startup and SHALL keep their `is_builtin` flag set so they cannot be deleted via the admin API: `super_admin` (SSO config + every permission below), `admin` (day-to-day administration: user.read, user.invite, sso.manage, policy._, host._, alert._), `senior_analyst` (investigate + take destructive action: host.read, host.isolate, host.kill_process, host.run_script, alert._), `analyst` (investigate + comment + escalate: host.read, process.read, alert.read, alert.comment), and `auditor` (read-only including audit.read). The `sso.manage` action gates reading and mutating the deployment's stored OIDC configuration; it is held by `admin` explicitly and by `super_admin` through its wildcard grant, and no other role holds it. The break-glass user MUST be bound to `super_admin` at the deployment-wide scope. SSO-provisioned users MUST default to `analyst` at the deployment-wide scope; the system MUST NOT auto-elevate any role from a SSO claim. The `*.*` notation above (`policy.*`, `host.*`, `alert.*`) is prose shorthand for the concrete per-domain action identifiers each role is granted; the seeds expand it to explicit actions in the policy bundle, and only `super_admin` holds a literal wildcard (`*`) grant. This keeps the seeds consistent with the UI permission-set expansion requirement, which returns concrete action identifiers rather than a wildcard token.

#### Scenario: Roles are seeded on first boot

- **GIVEN** an empty `roles` table
- **WHEN** the server boots
- **THEN** exactly the five seeded roles exist with `is_builtin=1`
- **AND** the break-glass user (when present) is bound to `super_admin` at the deployment-wide scope

#### Scenario: Built-in role cannot be deleted

- **GIVEN** an authenticated `super_admin`
- **WHEN** the operator attempts to delete a role with `is_builtin=1`
- **THEN** the server returns a typed error and does not modify the role

#### Scenario: Admin holds sso.manage; analyst does not

- **GIVEN** the seeded roles
- **WHEN** the chokepoint evaluates the `sso.manage` action
- **THEN** an actor bound to `admin` or `super_admin` is allowed
- **AND** an actor bound to `senior_analyst`, `analyst`, or `auditor` is denied with reason `no_matching_rule`

### Requirement: Role bindings carry a scope so future scoping is non-breaking

Every role binding SHALL carry a `scope_type` from the set `{'global', 'host_group', 'host'}` and a `scope_id`. The product is a single-instance deployment, so the current release SHALL enforce only `scope_type='global'` (with `scope_id='*'`), which means "deployment-wide". A binding with a non-`global` `scope_type` MUST be persisted but MUST NOT be honored by the chokepoint until the corresponding scope resolver ships. A binding MAY carry an `expires_at`; an expired binding MUST be treated as if it did not exist when the chokepoint evaluates a request.

#### Scenario: Deployment-wide binding grants the action

- **GIVEN** a role binding with `scope_type='global'`, `scope_id='*'`, and the role granting the requested action
- **WHEN** the chokepoint evaluates a request for that action
- **THEN** the decision is `{allow: true, reason: "granted"}`

#### Scenario: Host-scoped binding does not grant the action in the current release

- **GIVEN** a role binding with `scope_type='host'` and `scope_id` matching the resource host id
- **WHEN** the chokepoint evaluates a request that would only be authorized via the host scope
- **THEN** the decision is `{allow: false, reason: "scope_not_yet_supported"}`
- **AND** the audit row records the deny decision so the operator can see scopes are not yet honored

#### Scenario: Expired binding is ignored

- **GIVEN** a role binding whose `expires_at` is in the past
- **WHEN** the chokepoint loads the actor's bindings
- **THEN** the expired binding is not part of the evaluation input
- **AND** if no other binding grants the action, the decision is deny

### Requirement: Authorization decisions sub-millisecond at p99

The system SHALL evaluate the authorization chokepoint at p99 latency under 1 millisecond on the deployment's production hardware. The benchmark harness MUST run on every authorization-touching pull request, and a regression that pushes p99 above 1 ms SHALL fail the build. The benchmark MUST cover allow and deny paths and MUST use the seeded roles plus a representative role-binding fan-out.

#### Scenario: Benchmark passes on the merge candidate

- **GIVEN** a pull request that touches the authorization engine, the policy bundle, or the action registry
- **WHEN** continuous integration runs the authorization benchmark
- **THEN** the recorded p99 over the standard input set is below 1 millisecond
- **AND** the build passes

#### Scenario: Benchmark regression blocks the build

- **GIVEN** a pull request whose change pushes the benchmark p99 above 1 millisecond
- **WHEN** continuous integration runs the benchmark
- **THEN** the build fails and the PR cannot be merged until the regression is addressed

### Requirement: Service-account management actions are registered and admin-scoped

The system SHALL register the actions `service_account.read`, `service_account.create`, `service_account.rotate`, and `service_account.revoke` in the authorization action enumeration, mirrored in the policy bundle so the build-time parity check holds. These actions SHALL be granted to the seeded `admin` role; `super_admin` covers them via its wildcard. The service-account management endpoints SHALL funnel through the chokepoint on these actions like every other privileged action.

#### Scenario: Admin holds the service-account actions

- **GIVEN** an operator with the seeded `admin` role
- **WHEN** the chokepoint evaluates a `service_account.create` request
- **THEN** the decision is allow

#### Scenario: A role without the grant is denied

- **GIVEN** an operator with only the `analyst` role
- **WHEN** the chokepoint evaluates a `service_account.create` request
- **THEN** the decision is deny with the no-matching-rule reason

### Requirement: A service-account actor is evaluated by the chokepoint but is never session-fresh

The system SHALL resolve a verified service-account access token to an actor carrying the service account's bound role, evaluated by the same authorization chokepoint as a human actor. A service-account actor SHALL never be considered session-fresh. The reauth freshness gate, which protects destructive actions for interactive human sessions, SHALL NOT apply to a service-account actor; whether a service account may perform a destructive action SHALL be determined solely by whether its bound role grants that action.

#### Scenario: Service-account actor authorized purely by role

- **GIVEN** a service account whose bound role grants `host.isolate`
- **WHEN** it calls the host-isolate endpoint with a valid access token
- **THEN** the chokepoint allows the action without requiring session freshness

#### Scenario: Role without the action is denied regardless of token validity

- **GIVEN** a service account whose bound role does not grant `host.isolate`
- **WHEN** it calls the host-isolate endpoint with a valid access token
- **THEN** the chokepoint denies the action

### Requirement: User management is gated by a dedicated admin action

The system SHALL register the action `user.manage` in the authorization action enumeration, mirrored in the policy bundle so the build-time parity check holds. `user.manage` SHALL be granted to the seeded `admin` role; `super_admin` covers it via its wildcard. The user-management mutation endpoints SHALL funnel through the chokepoint on `user.manage`, and the user-listing endpoint SHALL funnel through the chokepoint on the existing `user.read` action, like every other privileged action.

#### Scenario: Admin holds the user-management action

- **GIVEN** an operator with the seeded `admin` role
- **WHEN** the chokepoint evaluates a `user.manage` request
- **THEN** the decision is allow

#### Scenario: A role without the grant is denied

- **GIVEN** an operator with only the `analyst` role
- **WHEN** the chokepoint evaluates a `user.manage` request
- **THEN** the decision is deny with the no-matching-rule reason

### Requirement: Operators manage users and their roles through an audited API

The system SHALL expose an admin API that lists users with their effective role and account status, sets a user's role, and enables or disables a user. Setting a role SHALL replace the user's global role bindings transactionally so a user holds exactly one global role afterward. Every applied mutation SHALL emit an audit row recording the acting operator and the target user: a role change emits `authz.role_binding.update` (or `authz.role_binding.create` when the user had no prior global binding, or `authz.role_binding.delete` when access is cleared), and a status change emits `user.disabled` or `user.enabled`. A mutation that changes nothing SHALL succeed without emitting an audit row.

#### Scenario: Listing users returns each user with role and status

- **GIVEN** an authenticated operator holding `user.read`
- **WHEN** they call the user-list endpoint
- **THEN** the response carries each user with their effective role and account status

#### Scenario: Setting a role replaces the global binding and is audited

- **GIVEN** a user bound to `analyst` and an operator holding `user.manage`
- **WHEN** the operator sets that user's role to `senior_analyst`
- **THEN** the user holds exactly one global binding, for `senior_analyst`
- **AND** an `authz.role_binding.update` audit row records the acting operator, the target user, and the previous and new roles

#### Scenario: Disabling a user is audited and blocks access

- **GIVEN** an active user and an operator holding `user.manage`
- **WHEN** the operator disables that user
- **THEN** the user's account status becomes disabled
- **AND** a `user.disabled` audit row records the acting operator and the target user

### Requirement: User-management guardrails prevent lockout and privilege escalation

The system SHALL reject a mutation that would leave the deployment with no active admin: demoting or disabling the last active user holding `admin` or `super_admin` SHALL fail. This invariant SHALL hold under concurrency: two mutations that each individually pass the check SHALL NOT both commit if together they would remove the last active admin. An operator SHALL NOT change their own role or disable themselves through this surface. A user with the break-glass flag SHALL NOT be modified through this surface. Only a `super_admin` actor MAY grant the `super_admin` role, and an `admin` actor SHALL NOT modify a user who currently holds `super_admin`. Each rejected mutation SHALL leave all persisted state unchanged.

#### Scenario: The last admin cannot be demoted or disabled

- **GIVEN** exactly one active user holds an admin-tier role
- **WHEN** an operator attempts to demote or disable that user
- **THEN** the request is rejected and the user keeps the admin-tier role and active status

#### Scenario: An operator cannot change their own role

- **GIVEN** an operator holding `user.manage`
- **WHEN** they attempt to change their own role or disable themselves
- **THEN** the request is rejected and their role and status are unchanged

#### Scenario: Break-glass users cannot be modified

- **GIVEN** a user with the break-glass flag set
- **WHEN** an operator attempts to change that user's role or status
- **THEN** the request is rejected and the break-glass user is unchanged

#### Scenario: Only a super admin may grant the super admin role

- **GIVEN** an operator whose own role is `admin`
- **WHEN** they attempt to set another user's role to `super_admin`
- **THEN** the request is rejected and the target user's role is unchanged

#### Scenario: Concurrent demotions cannot both remove the last admin

- **GIVEN** exactly two active users hold an admin-tier role
- **WHEN** both are disabled (or demoted) concurrently
- **THEN** exactly one mutation succeeds and the other is rejected
- **AND** at least one active admin-tier user remains
