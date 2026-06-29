# Authorization

Every privileged operator action in the EDR server passes through a single chokepoint that decides allow / deny based on the calling operator's role bindings and the action being attempted. A deny becomes a `403` on the wire with an `X-Edr-Authz-Reason` header naming the policy's verdict; the same row lands in the audit log with the actor + the resource attached.

The chokepoint enforces unconditionally: every privileged action is evaluated against the calling actor's role bindings, and a policy deny becomes a `403` on the wire.

## Seeded role matrix

Five built-in roles ship with the server. Their grants are the source of truth in `server/identity/internal/authz/policy/data/roles.json`; this section is a human-readable mirror.

| Role | Reads | Writes / Destructive |
| --- | --- | --- |
| `super_admin` | everything | everything (`*` wildcard) |
| `admin` | host, process, alert, policy, enrollment, user | host.{isolate, kill_process, run_script}, alert lifecycle (acknowledge, resolve, reopen, comment), policy CRUD, enrollment.{revoke, rotate_token}, user.invite |
| `senior_analyst` | host, process, alert | host.{isolate, kill_process, run_script}, alert lifecycle (acknowledge, resolve, reopen, comment) |
| `analyst` | host, process, alert | alert.comment |
| `auditor` | host, process, alert, audit | (none) |

`super_admin` is the break-glass account's role at first boot. SSO operators provisioned via JIT default to `analyst`; promote them from the Users page in Admin settings (or, as a break-glass alternative, the SQL pattern below).

The five-role layout is current. Role bindings are managed through the admin API + Users page (see below); the `INSERT IGNORE` seed at boot guarantees the role rows exist, and the `is_builtin=1` column protects the seeded roles from accidental deletion.

## How a 403 reads on the wire

When the chokepoint denies, the response is:

```http
HTTP/1.1 403 Forbidden
X-Edr-Authz-Reason: <reason>
Content-Type: application/json
Cache-Control: no-store

{"error": "forbidden"}
```

When the deny is `reauth_required` (destructive action on a session past the freshness window), the body is structured so the UI can prompt for re-authentication inline:

```http
HTTP/1.1 403 Forbidden
X-Edr-Authz-Reason: reauth_required
Content-Type: application/json

{
  "error": "reauth_required",
  "challenge": {
    "auth_method": "oidc",
    "reauth_url": "/api/auth/login?reauth=1"
  }
}
```

Reading the `X-Edr-Authz-Reason` header (or the matching `audit_events` row's `payload.reason`) is the entry point for any diagnosis flow.

### Reason codes

| `X-Edr-Authz-Reason` | What it means | What to do |
| --- | --- | --- |
| `granted` | Decision was Allow. Never appears on a 403; documented for completeness because the audit row uses the same field. | (none) |
| `no_matching_rule` | The actor's role bindings don't grant the action. | Assign the appropriate role from the Users page in Admin settings (or SQL, see below). |
| `reauth_required` | The actor's session is past the reauth window (default 30m). The role grants the action; the operator just needs to re-prove possession of credentials. | UI handles this automatically via the reauth modal. If a non-UI client hits it, follow `challenge.reauth_url` and retry. |
| `scope_not_yet_supported` | The actor has a `host_group` or `host` scoped role binding. The current release only honours the deployment-wide `global` scope. | Persist a `global`-scoped binding instead: `host_group` / `host` scopes are coming soon. |
| `action_not_registered` | The handler called `Allow` with an action string outside `RegisteredActions`. | Server bug. File a ticket; the offending handler likely passed a string literal instead of a typed `api.Action` constant. |
| `no_actor` | The chokepoint was reached without an authenticated session on context. | Server bug: the session middleware is misconfigured for the route. Check the route's middleware chain. |

The audit-log row's `payload` carries `reason` matching the header. The granting role is not on the payload today: derive it by joining `role_bindings` for the actor's `user_id` if needed.

## Binding a role to a user

The primary path is the Users page in Admin settings (`/admin/settings/users`): an `admin` lists operators, sets each one's role, and enables or disables access, all audited (`authz.role_binding.*` / `user.disabled` / `user.enabled`). The API behind it is `GET /api/settings/users`, `PUT /api/settings/users/{id}/role`, and `PUT /api/settings/users/{id}/status`, gated on `user.read` / `user.manage`. The UI enforces the same guardrails the server does: the last admin cannot be demoted or disabled, an operator cannot change their own role, break-glass accounts are immutable here, and only a `super_admin` may grant `super_admin`.

To set an operator's role _before_ their first sign-in, pre-provision them from the same Users page ("Add user"): enter an email and a role and the server stages a pending account (`POST /api/settings/users`, gated on `user.invite`, audited as `user.provisioned`). The staged row shows a "Pending" badge until that email first authenticates via SSO, at which point the OIDC provisioner adopts the row, activates it, and binds the pre-assigned role instead of defaulting to `analyst`. Matching is on the verified email claim, and adoption is honored even when JIT auto-provisioning is disabled (staging is an explicit admin decision, distinct from JIT-creating an unknown subject). `super_admin` is never offered and is rejected unless the acting operator is itself a `super_admin`.

The SQL pattern below remains as a break-glass alternative (for example, recovering a deployment that has no usable admin session). The shape mirrors `server/identity/bootstrap/schema.go`:

```sql
INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id)
VALUES (
  <user_id>,           -- users.id
  'admin',             -- one of: super_admin, admin, senior_analyst, analyst, auditor
  'global',            -- the current release honours only the deployment-wide scope
  '*'                  -- wildcard for the deployment-wide scope
);
```

The `(user_id, role_id, scope_type, scope_id)` tuple is the `uk_role_bindings` UNIQUE key (the row's primary key is an auto-increment `id`). Re-running the same INSERT raises a duplicate-key error rather than a silent no-op, which is the safer direction. To upsert deliberately, add `ON DUPLICATE KEY UPDATE`. Note the admin Users page models a user as a single global role: setting a role there replaces the user's global bindings, so a hand-written multi-binding row is collapsed the next time an admin edits that user.

To revoke: `DELETE FROM role_bindings WHERE user_id = <user_id> AND role_id = 'admin'`. Sessions don't get bounced automatically; the next chokepoint call reads fresh bindings via `Service.LoadActor`, so the change takes effect on the next request.

## Behind the chokepoint

The implementation lives in `server/identity/internal/authz/`. `Engine.Allow` evaluates a single `data.edr.authz.decision` query against an embedded OPA / Rego module (`server/identity/internal/authz/policy/edr.rego`); the role-grant table is `policy/data/roles.json`. Every call also threads through `AuditRecorder.Record` so the deny dashboard reads from the same table the chokepoint writes to.

See [`architecture.md`](architecture.md) for the bounded-context split and [`0004-modular-monolith-bounded-contexts.md`](adr/0004-modular-monolith-bounded-contexts.md) for why the chokepoint sits inside the `identity` context but exposes a public `api.AuthZ` interface every other context calls.

## UI capability gating

The web UI hides navigation entries and action controls an operator's role does not confer, so an analyst never sees a Kill process button or an Application control tab they cannot use. This is a usability layer only: the chokepoint above remains the sole security boundary, and the UI keeps handling a `403` gracefully (it never relies on hiding as a control). See [`0012-capability-based-ui-gating.md`](adr/0012-capability-based-ui-gating.md) for the decision and trade-offs.

The UI learns what to show from the session probe. `GET /api/session` returns a `permissions` array: the flat set of action identifiers the operator's role bindings confer, computed server-side from the same `roles.json` grants the chokepoint evaluates (the `super_admin` `*` wildcard expanded to the concrete action set; the wire never carries `*`). The UI gates on those exact identifiers, so a gate maps 1:1 to a chokepoint check and to an `authz.<action>` audit row: one vocabulary end to end, no separate role-to-feature mapping in the frontend.

The permission set the UI gates on is a session-lifetime snapshot, taken when the session probe runs. Server enforcement and UI display therefore update on different schedules, and this is not a contradiction: the chokepoint reads fresh bindings on the next request (see "Binding a role to a user" above), so a role change is enforced immediately server-side; but the UI keeps showing affordances from its cached snapshot until the operator's next sign-in or an explicit refresh. As a self-heal, when the server denies an action the UI believed was permitted (the snapshot was stale), the UI refetches the session permission set (deduplicated so a burst of denials collapses to a single request) and hides the now-stale affordance on the next render.

## Test coverage

Three test layers protect the chokepoint contract:

- `server/identity/internal/authz/engine_test.go` - `TestAllow_RoleActionMatrix` pins every (role, action) verdict at the engine level; `TestAllow_EveryRegisteredActionGrantedSomewhere` asserts every `RegisteredActions` constant is granted by at least one seeded role (so an action added without a matching grant in `roles.json` doesn't ship as a permanent `no_matching_rule`).
- `server/identity/internal/authz/policy_test.go` - `TestPolicy_ActionsParity` keeps `RegisteredActions`, the embedded `actions.json` bundle, and the role grants in `roles.json` in sync.
- `test/arch/chokepoint_coverage_test.go` - `TestEveryPrivilegedHandlerCallsHTTPGate` walks every operator handler file and asserts each references `HTTPGate`. A new privileged route added without the chokepoint call fails the build with a directed message.
