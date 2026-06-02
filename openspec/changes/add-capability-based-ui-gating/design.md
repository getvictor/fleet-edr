# Design: capability-based UI gating

This note records the implementation-level shape that the behavioral spec deltas deliberately leave
out. The build-versus-buy decision (bespoke seam vs a client authorization library) and the
permissions-not-roles rationale live in ADR-0012; this document covers how the pieces fit.

## Permission set shape

The session-probe response gains one additive field: a flat array of action identifiers drawn from
the existing action registry (`server/identity/internal/authz/policy/data/actions.json`). Example for
an `analyst` session:

```jsonc
// GET /api/session
{
  "user": { "id": 2, "email": "analyst@qa.local" },
  "csrf_token": "…",
  "auth_method": "oidc",
  "permissions": ["host.read", "process.read", "alert.read", "alert.comment"]
}
```

The identifiers are the same strings the chokepoint enforces and the audit log records
(`authz.<action>`), so a UI gate, a backend check, and an audit row all speak one vocabulary.

## How the set is computed

The set is the union of the action grants across the active session's role bindings, evaluated at the
deployment-wide scope (the only scope enforced in wave 1). It is derived from the **same** role
bindings the session middleware already loads to build the request actor, so no new persisted state
and no new cross-request in-process state is introduced (ADR-0010).

The `super_admin` role grants `*`. The server expands that wildcard against the action registry before
serializing, so the wire never carries `*` and the UI never has to special-case it. Expanding
server-side keeps the single source of truth on the server.

## UI seam

A single capability provider is seeded from the existing session bootstrap and exposes one check
(conceptually `can(action)` / a `<Can action="…">` wrapper). Every gated affordance goes through it:

- Navigation entries gate on the read action for their destination. The full wave-1 mapping:
  - Hosts (`/`) on `host.read`.
  - Alerts (`/alerts`) on `alert.read`.
  - Application control (`/app-control`) on `application_control.read`.
  - Coverage (`/coverage`) and the per-rule documentation pages are not gated by a dedicated read
    action in wave 1 (no `coverage.read` / `rule.read` exists in the action registry); they remain
    visible to any authenticated operator. If a future wave adds such an action, this mapping grows
    with it.
- Action controls gate on the action they perform (Kill process on `host.kill_process`; isolate on
  `host.isolate`; run script on `host.run_script`; alert lifecycle controls on their respective
  actions).

Centralizing on one seam is the load-bearing decision: it keeps role→feature logic out of the UI
entirely (the UI only ever reads the server-computed set) and makes a future swap to a library - should
wave-2 scoped grants ever require client-side conditional evaluation - mechanical rather than a rewrite.

## Staleness and graceful denial

The permission set is a snapshot taken at session bootstrap; its lifetime is the session's. A role
change made mid-session is therefore not reflected until the next login or an explicit refetch. This
matches the chokepoint's existing "takes effect on next sign-in" behavior.

Two consequences are specified as behavior:

1. Any authorization denial the UI did not anticipate renders a friendly no-access state, never a raw
   `API error: 403`.
2. On such a denial the UI refetches the session permission set, self-healing the staleness window so
   the stale affordance is hidden on subsequent renders.

Because the server enforces every action regardless, an absent or stale permission set can only change
what is shown, never what is allowed.

## Non-goals

- Per-resource (`host_group` / `host`) scoped gating - depends on wave-2 scoped role bindings.
- Pushing permission changes to a live session without a refetch.
- Any client-side evaluation of authorization conditions, or a client authorization library - see
  ADR-0012 for the trigger that would reopen that choice.
