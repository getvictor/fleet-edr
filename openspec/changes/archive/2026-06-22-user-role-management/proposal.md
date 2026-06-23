## Why

Role promotion is SQL-only today. `docs/authz.md` documents the pattern an operator runs by hand:

```sql
INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id) VALUES (<uid>, 'senior_analyst', 'global', '*');
```

That was a deliberate wave-1 shortcut (PRs #117-#134 shipped the `role_bindings` table, the OPA chokepoint, and OIDC JIT landing every new user in `analyst`). It does not scale past the pilot: every operator change is a DBA ticket, and there is no audited, in-product record of who holds which role. Every commercial EDR (CrowdStrike Falcon, SentinelOne, Defender for Endpoint, Carbon Black, Elastic Security) ships role management as an in-product admin surface; pilot customers expect to promote an analyst, revoke access, and see who has access without touching the database. Issue #135 is the second half of the SSO + RBAC story (#66), following the SSO config UI (#375) and service-account auth (#376), and it reuses the same admin-settings shell those two built.

## What Changes

- Add a `user.manage` authorization action, registered in the action enumeration and mirrored in the policy bundle (the build-time parity check holds), granted to `admin` (and `super_admin` via its wildcard). Listing users continues to use the existing `user.read` action.
- Add an audited admin API under the existing operator-session + CSRF boundary:
  - `GET /api/settings/users` lists users with their effective role and account status (gated on `user.read`).
  - `PUT /api/settings/users/{id}/role` sets a user's role (gated on `user.manage`).
  - `PUT /api/settings/users/{id}/status` enables or disables a user (gated on `user.manage`).
- Model a user's role as a single global binding for wave-2 (the five seeded roles, `scope_type='global'`). Setting a role replaces the user's global bindings transactionally, matching how OIDC JIT already assigns exactly one role. The store stays binding-oriented underneath so the OIDC group-reconciliation work (#136) and wave-3 multi-binding are not blocked.
- Enforce guardrails that prevent lockout and privilege escalation: the last admin cannot be demoted or disabled, an operator cannot change their own role or disable themselves, break-glass users cannot be modified through this surface, and only a `super_admin` actor may grant the `super_admin` role (the UI never offers it, mirroring the service-account rule).
- Emit an audit row on every mutation: `authz.role_binding.create` / `authz.role_binding.update` / `authz.role_binding.delete` for role changes (payload carries from/to), and `user.disabled` / `user.enabled` for status changes, recording the acting operator and the target user.
- Add a Users page to the Admin settings shell (`/admin/settings/users`): a table of operators with an inline role selector and an enable/disable control, gated on the new permission constants via the `useCan()` seam. Add the API client calls (CSRF on mutation).
- Update `docs/authz.md`: the SQL pattern becomes the documented break-glass alternative, not the primary path.

Out of scope (deferred): inviting brand-new users (no email/local-account-creation path exists yet; new operators still arrive via OIDC JIT or break-glass), multi-tenant / host-group scope assignment (wave-3), custom roles or per-action grant editing (wave-3), and OIDC group-claim to role mapping (#136, separate change, converges on the same table).

## Capabilities

### Modified Capabilities

- `server-identity-authorization`: register the `user.manage` action (admin-scoped); add the audited admin API that lists users and mutates their role bindings and account status through the chokepoint, the single-global-binding wave-2 role model, and the anti-lockout / anti-escalation guardrails.
- `web-ui`: add the user-management page to the Admin settings area, gated on `user.read` / `user.manage`.

## Impact

- Code: `server/identity/api/authz.go` (+`user.manage` action), `server/identity/api/audit.go` (+role-binding and user-status audit actions), `server/identity/internal/authz/policy/data/{actions,roles}.json`, `server/identity/internal/users` (+admin list, +status update), `server/identity/internal/rbac` (+set-role replace, +list-all-bindings, +active-admin count), a new `server/identity/internal/useradmin` handler package, `server/identity/bootstrap` (wiring), `server/cmd/fleet-edr-server/main.go` (route allowlist), and the React UI (`ui/src/` new Users page + API client + permission constants).
- Data: none. The `users` (with `status`) and `role_bindings` (with `expires_at`) tables already carry every column this change needs; no migration.
- APIs: three new authed routes under `/api/settings/users`. No change to the agent protocol, the event schema, or any existing endpoint.
- Audit invariant: every role and status mutation emits an audit row recording the acting operator and the affected user; a no-op (setting the role a user already has, with no change) need not audit.
- Rollback is a code revert; no schema to unwind. Deployments keep working with the SQL break-glass path.
