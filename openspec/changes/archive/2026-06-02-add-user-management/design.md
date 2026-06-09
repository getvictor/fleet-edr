## Context

The user-management plan tracked at
`https://github.com/getvictor/fleet-edr/issues/66` was authored before ADR-0004 carved
`server/` into five bounded contexts (`identity`, `endpoint`, `rules`,
`response`, `detection`). The original plan referenced flat-tree packages
(`server/users`, `server/sessions`, `server/authn`, `server/authz`, `server/audit`,
`server/auth/oidc`, `server/auth/breakglass`, `server/seed/admin.go`) that no longer
exist in that shape. This design re-targets every load-bearing decision in the plan to
the bounded-context layout while keeping the plan's product choices intact (Okta OIDC as
the single SSO library, OPA / Rego as the authz engine, WebAuthn-mandatory break-glass,
dual-emit audit log, single-instance deployment).

The current state, as of this proposal:

- `identity` context owns `users`, `sessions`, login, and the seed-admin flow under
  `server/identity/internal/{users,sessions,authn,seed}` (renamed during the modular-
  monolith migration). The session capability is captured in
  `openspec/specs/ui-authentication-session/spec.md`. Login is local-password only;
  every authenticated user is functionally super-admin.
- `endpoint`, `rules`, `response`, `detection` each own their own tables, schema migrations,
  and admin-side handlers. Cross-context calls funnel through each context's `api/`
  package; arch-go (`arch-go.yml` + `test/arch/arch_test.go`) hard-fails CI on a
  disallowed import. There is one exception baked in by ADR-0004 phase 5: cross-context
  FKs were removed and replaced with code-level validation; we will not reintroduce them.
- The audit story today is "structured slog records emitted by individual handlers" with
  no durable table, no read endpoint, and no central recorder.

## Goals / Non-Goals

**Goals:**

- Land wave 1 of the plan (Okta OIDC + break-glass + RBAC + audit) as
  one cohesive change inside the existing bounded-context architecture, with arch-go
  passing at every PR boundary.
- Expose the authz chokepoint and the audit recorder through `server/identity/api/` so that
  every other context calls into identity through its public surface - no inversion of the
  ADR-0004 import rules, no new "shared internal" package.
- Keep the agent ↔ server protocol, the events schema, and the host-token middleware
  unchanged. None of this work touches the agent.
- Ship the chokepoint enforcing from boot. Wave-1 has zero existing deployments to
  migrate, so the audit-only "shadow" rollout used by retrofits doesn't apply here:
  the deny dashboard's value is the same once enforcement is on from day one.

**Non-Goals:**

- Multi-IdP per deployment; per-deployment SSO mixing; SCIM; SAML. Wave 2 / wave 3.
- Customer-authored Rego bundles. Engine supports it; not exposed.
- Group → role mapping driven by Okta `groups` claim. Wave 2.
- Forgot-password / self-service password reset for break-glass. Recovery is the
  documented operator procedure.
- API tokens (`identity.kind = 'api_token'`). Reserved schema slot; wave 2 deliverable.
- Host-group / host-scoped read filtering ("show me only the alerts I can see"). The data
  model is ready (`role_bindings.scope_type`, `scope_id`); MVP punts on the SQL filter
  side and relies on the deployment-wide `alert.read` grant.

## Decisions

### Single capability boundary: identity context owns authn, authz, and audit

**Decision:** Keep all three new specs (`server-identity-authentication`,
`server-identity-authorization`, `server-identity-audit-log`) inside the existing
`identity` bounded context rather than creating a new context per concern.

**Rationale:** Authn issues an `Actor`, authz consumes the `Actor`, audit records
decisions made by authz. They share a session middleware, a request-context shape, a
schema-migration boundary, and a deployment surface. Splitting them into separate
contexts would force every other context's privileged handler to know about three
upstream `api/` packages instead of one. ADR-0004 explicitly prefers a small number of
cohesive contexts over per-table fragmentation; the same logic applies here. The three
specs exist as separate documents so each can evolve independently (an audit-retention
change, for example, should not require re-validating authz scenarios), but the
runtime code lives under `server/identity/internal/`.

**Alternatives considered:**

- Separate `authz` context. Rejected - every other context would need to import both
  `identity/api` (for the actor) and `authz/api` (for the chokepoint), doubling the
  cross-context surface for no practical isolation benefit.
- Audit as a cross-cutting "shared" package outside any context. Rejected - there is
  no shared-package layer in the bounded-context layout; ADR-0004 is explicit that
  cross-context calls go through `<other>/api`. A new shared layer would punch a hole
  in arch-go's allow-list.

### Public API surface

`server/identity/api/` gains exactly four exports beyond what's there today:

```go
package api

// Actor is built once by session middleware and threaded through context.Context.
// Other contexts read it via api.ActorFromContext(ctx).
type Actor struct {
    UserID       int64
    IsBreakglass bool
    AuthMethod   string                 // "oidc" | "local_password"
    Roles        []RoleBinding
    SessionFresh bool                   // last fresh auth event within the reauth window
}

// AuthZ is the chokepoint. Every privileged handler in detection/rules/response/endpoint
// calls AuthZ.Allow before performing the side effect.
type AuthZ interface {
    Allow(ctx context.Context, action Action, resource Resource) (Decision, error)
}

// Audit is the recorder. authz.Allow calls it for every decision; handlers that want to
// record state-changing actions distinct from authz decisions call it directly.
type Audit interface {
    Record(ctx context.Context, e Event) error
}

// Action constants live here, not as string literals at call sites. CI fails the build
// if a string literal is used in an Allow call (vet rule + arch-go).
const (
    ActionHostRead       Action = "host.read"
    ActionHostIsolate    Action = "host.isolate"
    ActionHostKillProcess Action = "host.kill_process"
    // ... full registry, mirrored in actions.json
)
```

Identity's `bootstrap.New(deps)` returns concrete implementations (`AuthZ`, `Audit`,
`SessionMiddleware`) wired to MySQL + the embedded OPA engine. `cmd/fleet-edr-server/main.go`
constructs the identity bootstrap once and passes the resulting `AuthZ` and `Audit`
handles into every other context's `bootstrap.New`. arch-go's allow-list already permits
`detection / rules / response / endpoint → identity/api`; this change adds the new symbols
to that surface, no rule edits needed.

### Schema ownership across contexts

Identity owns the new identity-side tables. The product is a single-instance deployment
(each customer runs their own server), so no `tenant_id` partitioning column is added to
any context's tables.

- `server/identity/internal/store/schema.sql` - adds `identities`, `roles`,
  `role_bindings`, `audit_events`, `bootstrap_tokens`, `webauthn_credentials`, plus the
  additive columns on `users` and `sessions`. Existing migrations remain untouched;
  follow the additive-only pattern documented for ADR-0004 phase 5.

Apply order in `cmd/fleet-edr-server/main.go` is unchanged
(`identity → endpoint → rules → response → detection`).

No cross-context FKs. The `role_bindings.user_id → users.id` FK lives entirely inside
identity.

### Authorization engine: embedded OPA / Rego

The plan locks the engine choice to OPA/Rego with explicit revisit conditions; we
preserve that decision verbatim. Engine wiring:

- Policies live at `server/identity/internal/authz/policy/*.rego`, baked via `embed`.
- The compiled `rego.PreparedEvalQuery` is constructed once in
  `identity/internal/authz/engine.go` at boot. Policy changes ship as a new binary
  rather than a runtime reload, so there is no in-process refresh path to maintain.
- Per-decision latency budget is <1ms p99 measured in `identity/internal/authz/bench_test.go`;
  arch-go and golangci-lint allow the test target. A budget regression in CI is a
  release blocker, not a warning.

The action registry is dual-source-of-truth:

- `server/identity/api/actions.go` exports `Action` typed constants. Non-test code MUST
  import the constant; no string literals at call sites.
- `server/identity/internal/authz/policy/data/actions.json` lists the same names. Boot
  fails if the two diverge, and a Go test in `identity/internal/authz/tests/` enforces
  parity.

### Audit recording: dual-emit, deny-fail-soft

Every `AuthZ.Allow` call ends in an `Audit.Record(...)` call before the response is
written. The recorder:

1. Inserts into `audit_events`. A failure here logs at ERROR and increments
   `edr_audit_write_failures_total` (already wired through observability-instrumentation),
   but does not fail the user request.
2. Emits a structured slog record at INFO (allow) or WARN (deny / break-glass / error).
3. Adds OTel span attributes (`edr.audit.action`, `edr.audit.decision`, `edr.audit.reason`)
   on the active request span.

Sampling for read-only decisions defaults to 0.0 in MVP and is config-tunable; break-glass
actor forces sampling to 1.0 regardless of config.

### Sessions: existing capability extends, does not split

`ui-authentication-session` already owns the cookie + CSRF surface. We extend it rather
than introducing a parallel session capability. The deltas are:

- Two new columns on `sessions`: `identity_id BIGINT NULL`, `auth_method VARCHAR(32)`.
- Idle (8h) / absolute (24h) / reauth-window (30m) replace the flat 12h expiry.
- Break-glass sessions get tighter idle (15m) / absolute (1h) caps.
- The login endpoint now accepts authentication originated from either OIDC callback or
  break-glass; the cookie + CSRF mint is unchanged.

The new authentication capability owns the OIDC callback handler that ends in a session
mint; the session capability owns the cookie itself. The split is "who originates the
authentication" (new capability) vs "what the cookie behaves like once minted" (existing
capability). Both specs are updated in lockstep in this change.

### Break-glass surface: SSO-only login UI, separate path for emergency

`/login` no longer renders a password form. The break-glass surface lives at
`/admin/break-glass` (login) and `/admin/break-glass/setup` (token redemption +
WebAuthn registration). The optional reverse-proxy IP allowlist returns 404 for
off-allowlist callers so the path is not even acknowledged. This matches the plan's
resolved-decision section verbatim.

The seed flow is the only behavior break for an upgrading operator. `seed.Admin`
(now `server/identity/internal/seed/breakglass.go`) on first boot inserts a single-use
bootstrap token row and prints the redemption URL banner. Migration of an existing
`admin@fleet-edr.local` row sets `is_breakglass = 1`, nulls password fields, and
auto-issues a token whose URL is printed once on first start after upgrade. Token
redemption fully replaces the previous "lost the stderr password" recovery path
documented in the existing session spec.

## Risks / Trade-offs

- **Chokepoint enforces from boot.** With no upgrade path to retrofit, the chokepoint
  goes live in enforcing mode in the same PR that converts the last privileged handler.
  → Mitigation: tests gate on the absence of any handler that does not call
  `AuthZ.Allow` (a code-search rule plus a fixture-handler audit); the deny dashboard
  catches role-binding gaps within minutes of cutover.
- **OPA dependency footprint.** `opa/rego` brings in a sizable transitive tree; binary
  size and compile time grow noticeably. → Mitigation: documented in the plan;
  dependency-review CI flags unexpected bumps; budget set against a baseline measured at
  PR merge time.
- **Per-decision latency regressions.** A poorly written Rego rule can do quadratic work.
  → Mitigation: `opa test` + `opa eval --benchmark` in CI on every authz PR; the
  `<1ms p99` budget is enforced via `bench_test.go` failing the build.
- **Audit log volume during incidents.** A spike in deny decisions on a noisy handler
  could saturate the DB writer. → Mitigation: bounded-buffer async writer with the same
  back-pressure pattern as the event ingest queue (already proven under load in the
  detection context); buffer-overflow drops are themselves emitted as a slog WARN +
  OTel counter.
- **JIT provisioning auto-creating accounts from any Okta tenant.** Default
  `allow_jit_provisioning = true` for MVP per the plan; once a deployment ships, the
  customer is expected to flip it to `false` and rely on an explicit allowlist. →
  Mitigation: documented in the operator runbook; the audit row on JIT creation is at
  WARN so a SigNoz alert can fire on unexpected tenants.
- **Schema migration surface.** Identity runs additive migrations in this change.
  → Mitigation: the migration is additive; rollback is a redeploy of the prior binary,
  with the new tables / columns left harmlessly in place.

## Migration Plan

The plan lists six phases inside the wave-1 PR sequence. We preserve those, retargeted
to the bounded-context layout. Each phase is one PR; arch-go and golangci-lint pass at
every phase boundary.

1. **Schema + seeding (identity-only).** New identity tables, additive columns on
   `users` / `sessions`, the role-seeder loop, the rewritten `seed.Admin` →
   `seed.BreakGlassBootstrap`. No behavior change yet.
2. **Authz package enforcing from boot.** `server/identity/internal/authz` lands
   compiled. `identity/api` exports `AuthZ`, `Audit`, `Actor`. Every existing
   privileged handler is converted to call `AuthZ.Allow(...)` with the appropriate
   action constant. Deny decisions return 403 from cutover.
3. **Audit recorder + dual-emit live.** `audit_events` writes start happening; the slog
   / OTel emit path is wired through observability-instrumentation. Read endpoint
   shipped behind `audit.read` with audit-of-audit on its own access.
4. **OIDC + break-glass authn paths land.** OIDC discovery, callback, JIT, identity
   model. Break-glass bootstrap-token + WebAuthn registration. UI changes
   (`/login`, `/admin/break-glass`). Configurable but disabled by default
   (`auth.oidc.enabled = false`).
5. **Session middleware updates.** Idle / absolute / reauth timeouts; break-glass
   tighter caps. Reauth-window enforcement on destructive actions.
6. **Documentation.** Operator runbook for break-glass redemption + WebAuthn registration.
   Okta tenant setup guide. Role + permission matrix. SigNoz dashboard wiring for the
   audit-decision stream.

**Rollback strategy:** Every PR in this sequence is independently reversible.
Phase 2 is the cutover (deny decisions start returning 403); rollback to the prior
binary restores pre-chokepoint behavior. The new identity tables remain in place
across rollback - `bootstrap_tokens` and `webauthn_credentials` rows are harmless if
the seed flow is reverted.

## Open Questions

None. The plan's previously-open five questions were resolved before this change was
proposed (see the proposal's "Resolved decisions" reference). No new open questions
emerged from re-targeting to bounded contexts.
