# Authorization

Every privileged operator action in the EDR server passes through a
single chokepoint that decides allow / deny based on the calling
operator's role bindings and the action being attempted. A deny
becomes a `403` on the wire with an `X-Edr-Authz-Reason` header
naming the policy's verdict; the same row lands in the audit log
with the actor + the resource attached.

The chokepoint enforces by default. The
`EDR_AUTHZ_SHADOW_MODE=1` environment variable flips it into
audit-only mode (the policy still evaluates and the audit row is
still written, but the wire response is always allow); use that knob
when verifying role bindings against the audit log without flipping
enforcement on.

The boot log announces the posture explicitly:

```
INFO authz enforcement posture=ENABLED env_var=EDR_AUTHZ_SHADOW_MODE
```

(or `posture="SHADOW (denies audited but allowed)"` when the env
var is set). Grep `posture=ENABLED` in your log shipper to confirm
production deployments are enforcing.

## Seeded role matrix

Five built-in roles ship with the server. Their grants are the
source of truth in `server/identity/internal/authz/policy/data/roles.json`;
this section is a human-readable mirror.

| Role | Reads | Writes / Destructive |
|---|---|---|
| `super_admin` | everything | everything (`*` wildcard) |
| `admin` | host, process, alert, policy, enrollment, user | host.{isolate, kill_process, run_script}, alert lifecycle (acknowledge, resolve, reopen, comment), policy CRUD, enrollment.{revoke, rotate_token}, user.invite |
| `senior_analyst` | host, process, alert | host.{isolate, kill_process, run_script}, alert lifecycle (acknowledge, resolve, reopen, comment) |
| `analyst` | host, process, alert | alert.comment |
| `auditor` | host, process, alert, audit | — |

`super_admin` is the break-glass account's role at first boot. SSO
operators provisioned via JIT default to `analyst`; promote via the
SQL pattern below.

The five-role layout is wave-1; wave-2 will add an admin API for
role management. For wave-1 the `INSERT IGNORE` seed at boot
guarantees the rows exist, and the `is_builtin=1` column protects
them from accidental delete via a future admin endpoint.

## How a 403 reads on the wire

When the chokepoint denies, the response is:

```
HTTP/1.1 403 Forbidden
X-Edr-Authz-Reason: <reason>
Content-Type: application/json
Cache-Control: no-store

{"error": "forbidden"}
```

When the deny is `reauth_required` (Phase 5: destructive action on a
session past the freshness window), the body is structured so the
UI can prompt for re-authentication inline:

```
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

Reading the `X-Edr-Authz-Reason` header (or the matching
`audit_events` row's `payload.reason`) is the entry point for any
diagnosis flow.

### Reason codes

| `X-Edr-Authz-Reason` | What it means | What to do |
|---|---|---|
| `granted` | Decision was Allow. Never appears on a 403; documented for completeness because the audit row uses the same field. | — |
| `no_matching_rule` | The actor's role bindings don't grant the action. | Bind the appropriate role via SQL (see below). |
| `reauth_required` | The actor's session is past the reauth window (default 30m). The role grants the action; the operator just needs to re-prove possession of credentials. | UI handles this automatically via the reauth modal. If a non-UI client hits it, follow `challenge.reauth_url` and retry. |
| `scope_not_yet_supported` | The actor has a `host_group` or `host` scoped role binding. Wave-1 only honours `tenant` scopes. | Persist a `tenant`-scoped binding instead — `host_group`/`host` scopes are wave-2. |
| `action_not_registered` | The handler called `Allow` with an action string outside `RegisteredActions`. | Server bug. File a ticket; the offending handler likely passed a string literal instead of a typed `api.Action` constant. |
| `no_actor` | The chokepoint was reached without an authenticated session on context. | Server bug — the session middleware is misconfigured for the route. Check the route's middleware chain. |
| `resource_tenant_missing` | The handler built a `Resource` with an empty `TenantID`. | Server bug. The handler should call `api.ActorTenantID(ctx)` to populate the field. |
| `shadow_mode` | The deployment is running with `EDR_AUTHZ_SHADOW_MODE=1`. The deny was audited, but the wire response is allow. | Inspect the audit row to see which deny was masked, then unset the env var. |

The audit-log row carries `payload.reason` matching the header, plus
`payload.role` (the seeded role that would have granted, if any) and
`payload.shadow_mode=true` when shadow mode is on.

## Binding a role to a user (wave 1)

There is no admin API in wave 1; bindings go in via SQL. The shape
mirrors `server/identity/bootstrap/schema.go`:

```sql
INSERT INTO role_bindings (user_id, role_id, tenant_id, scope_type, scope_id)
VALUES (
  <user_id>,           -- users.id
  'admin',             -- one of: super_admin, admin, senior_analyst, analyst, auditor
  'default',           -- wave-1 deployments use a single tenant
  'tenant',            -- wave-1 honours only tenant scope
  '*'                  -- wildcard for the tenant scope
);
```

The `(user_id, role_id, tenant_id, scope_type, scope_id)` tuple is
the primary key — re-running the same statement is a duplicate-key
error rather than a silent no-op, which is the safer direction.

To revoke: `DELETE FROM role_bindings WHERE user_id = <user_id>
AND role_id = 'admin'`. Sessions don't get bounced automatically;
the next chokepoint call reads fresh bindings via
`Service.LoadActor`, so the change takes effect on the next request.

## `EDR_AUTHZ_SHADOW_MODE=1` (audit-only mode)

Set `EDR_AUTHZ_SHADOW_MODE=1` and restart to flip the chokepoint
into audit-only mode. Every `Allow` call still:

- evaluates the policy,
- writes the audit row with `payload.reason` set to what the verdict
  WOULD have been, and
- adds `payload.shadow_mode=true` to the row.

The wire response is always allow. Use this knob to verify role
bindings against the audit log without flipping enforcement on —
e.g. when standing up a fresh deployment and confirming the seeded
matrix matches the operators-and-roles you expect.

The boot log line for shadow mode reads:

```
INFO authz enforcement posture="SHADOW (denies audited but allowed)" env_var=EDR_AUTHZ_SHADOW_MODE
```

This is the canonical signal that audit-only mode is active. A
production log shipper should alert on this line — if shadow mode
landed in production accidentally, you want to know within minutes,
not by the time the next deploy runs.

## Behind the chokepoint

The implementation lives in `server/identity/internal/authz/`.
`Engine.Allow` evaluates a single `data.edr.authz.decision` query
against an embedded OPA / Rego module
(`server/identity/internal/authz/policy/edr.rego`); the role-grant
table is `policy/data/roles.json`. Every call also threads through
`AuditRecorder.Record` so the deny dashboard reads from the same
table the chokepoint writes to.

See `docs/architecture.md` for the bounded-context split and
`docs/adr/0004-modular-monolith-bounded-contexts.md` for why the
chokepoint sits inside the `identity` context but exposes a public
`api.AuthZ` interface every other context calls.

## Test coverage

Three test layers protect the chokepoint contract:

- `server/identity/internal/authz/engine_test.go` —
  `TestAllow_RoleActionMatrix` pins every (role, action) verdict at
  the engine level; `TestAllow_EveryRegisteredActionGrantedSomewhere`
  asserts every `RegisteredActions` constant is granted by at least
  one seeded role (so an action added without a matching grant in
  `roles.json` doesn't ship as a permanent `no_matching_rule`).
- `server/identity/internal/authz/policy_test.go` —
  `TestPolicy_ActionsParity` keeps `RegisteredActions`, the embedded
  `actions.json` bundle, and the role grants in `roles.json` in sync.
- `test/arch/chokepoint_coverage_test.go` —
  `TestEveryPrivilegedHandlerCallsHTTPGate` walks every operator
  handler file and asserts each references `HTTPGate`. A new
  privileged route added without the chokepoint call fails the
  build with a directed message.
