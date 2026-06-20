## MODIFIED Requirements

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
