# Design: admin user + role management (#135)

## Context

Wave-1 shipped the `role_bindings` table, the OPA chokepoint, and OIDC JIT (every new user lands in `analyst`). Promotion is SQL-only. This change adds the audited admin API + UI that #135 calls for, reusing the admin-settings shell from #375 (SSO) and #376 (service accounts). The scope decision (confirmed with the maintainer) is: manage existing users only (no invite flow), and present a single role per user.

## Decisions

### Single global binding per user (wave-2 role model)

The `role_bindings` table supports multiple bindings per user with scope and expiry. For wave-2 the UI presents exactly one role per user at `scope_type='global', scope_id='*'`, matching how OIDC JIT already binds a single role and the wave-2 ceiling (five seeded roles, global scope, stated in #135's out-of-scope). `PUT .../role` is therefore a transactional replace: delete the user's global bindings, insert one for the chosen role. This is idempotent and collapses any legacy multi-binding rows (created by hand via SQL) to the operator's explicit choice.

The store stays binding-oriented (`SetUserRole` returns the previous role set for the audit payload; `AllLiveBindings` returns every live binding). This keeps the door open for #136's per-sign-in group reconciliation and wave-3 multi-binding without reshaping the persistence layer; only the wave-2 UI imposes the single-role view.

### Endpoints under the existing settings boundary

The routes live under `/api/settings/users`, consistent with `/api/settings/sso` and `/api/settings/service-accounts`, so they ride the same operator-session + CSRF wrapper and the same allowlist mechanism (#463). They must be enumerated in the `main.go` session-protected allowlist or they fall through to the SPA catch-all and 302.

- `GET /api/settings/users` (gated `user.read`): list with effective role + status.
- `PUT /api/settings/users/{id}/role` (gated `user.manage`): body `{"role": "<seeded role>"}`.
- `PUT /api/settings/users/{id}/status` (gated `user.manage`): body `{"status": "active"|"disabled"}`.

Two narrow sub-resource PUTs (rather than one PATCH) keep each mutation's authorization, validation, and audit event unambiguous, mirroring the per-verb shape of the service-account handler.

### Guardrails (anti-lockout, anti-escalation)

The chokepoint answers "may this actor manage users." These additional invariants are enforced in the handler because they are about the *target*, not the actor's role:

1. **Last-admin protection.** Demoting or disabling the last active user holding `admin` or `super_admin` is rejected (`409 last_admin`). Prevents locking the deployment out of its own user management. Checked against a count of active (non-disabled) users with an admin-tier role, excluding the target.
2. **No self-management.** An operator cannot change their own role or disable themselves (`409 cannot_modify_self`). A mistaken self-demotion is the most likely lockout; self-changes go through break-glass.
3. **Break-glass is untouchable here.** A user with `is_breakglass=1` cannot be modified through this surface (`409 breakglass_immutable`); the break-glass account is the recovery path and is managed by its own ceremony.
4. **super_admin is restricted.** Only a `super_admin` actor may grant the `super_admin` role (`403 super_admin_forbidden`), and an `admin` actor cannot modify a user who currently holds `super_admin`. The UI never offers `super_admin` as a selectable role, mirroring the service-account rule; the server enforces it regardless of client.

These are deny-by-default: any ambiguity (target not found, role unknown) is a 4xx, never a silent partial change.

### Audit

Every applied mutation emits one synchronous audit row through the existing recorder:

- Role change: `authz.role_binding.update` with payload `{from: [...prev roles], to: "<role>"}`. A first-time grant on a user with no prior global binding records `authz.role_binding.create`; clearing to no role records `authz.role_binding.delete`. The wave-2 UI always sets a concrete role, so `update`/`create` dominate; the three constants exist so #136's reconciliation and any future "remove access" path are already covered.
- Status change: `user.disabled` / `user.enabled`, target type `user`.

A no-op (setting the role the user already has, or the status already in effect) returns `200` without an audit row, so the trail records changes, not clicks.

## Risks / trade-offs

- The single-role view hides legacy multi-binding state until the next `SetUserRole` normalizes it. Acceptable: the only source of multi-bindings today is hand-written SQL, and the list shows every live role so an operator can see the anomaly.
- Last-admin counting is a read-then-write check, not a DB constraint; under concurrent demotions it could in principle race. The operator population is tiny (handful of admins) and both writers funnel through one MySQL instance; the window is negligible and the cost of a true constraint (a trigger or a sentinel row) is not justified at wave-2 scale. Documented here rather than engineered around.

## Out of scope

Invite-new-user, multi-tenant / host-group scope, custom roles, OIDC group-to-role mapping (#136). All converge on the same `role_bindings` table additively.
