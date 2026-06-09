## Why

Today every authenticated operator is functionally a super-admin: there is one seeded local
account, no roles, no permissions, no SSO, and no audit log. The seed flow prints a
generated password to stderr on first boot - fine for a laptop demo, untenable for the pilot
deployments on the MVP roadmap and unworkable against the security-console competitive set
(CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint), all of which
ship SSO + RBAC + audit as table stakes. The product needs an identity boundary that an
enterprise buyer can sign off on, that future host-group / host scoped bindings can grow
into, and that a SOC team can use to reconstruct who did what to which host.

This change delivers wave 1 of the user-management plan tracked in
`https://github.com/getvictor/fleet-edr/issues/66`: Okta OIDC SSO as the primary login,
break-glass local account behind a separate URL with WebAuthn-mandatory bootstrap, embedded
Rego authorization with five seeded roles, and a dual-emit audit log. Wave 2 (API tokens,
host-group scopes, MFA for non-break-glass, SSO group mapping) and wave 3 (SAML, SCIM,
customer-authored Rego) are explicitly deferred to follow-on plans.

This OpenSpec change is the **spec-only** artifact: it adds the proposal, design, tasks,
and delta specs that describe the eventual behavior. The implementation lands in the
follow-up PRs enumerated in `tasks.md` (one phase per PR, each independently reviewable
against the requirements pinned by this change).

## What Changes

- Add Okta OIDC login at `/api/auth/login` and `/api/auth/callback` with PKCE S256, JIT
  provisioning to a seeded `analyst` role at the deployment-wide scope, and ID-token
  verification via discovery. Single global IdP per deployment; multi-IdP support is a
  follow-on feature.
- **BREAKING** for the bootstrap flow: replace the existing "print a generated password to
  stderr on first boot" seed with a single-use bootstrap token whose redemption URL is
  printed instead. Operator visits `/admin/break-glass/setup?token=…` to set a password
  (≥ 12 characters) and register a WebAuthn credential before the break-glass account is
  usable. WebAuthn carries the cryptographic factor; the password is the
  defense-in-depth length gate per CIS guidance for MFA-protected accounts. Migration of
  an existing `admin@fleet-edr.local` row flips it to break-glass and forces a token
  redemption before next login.
- Move ongoing break-glass login to a separate `/admin/break-glass` URL that is not linked
  from the SSO login page and that 404s for callers outside the optional reverse-proxy IP
  allowlist. Per-IP and per-email rate limits, P1 audit on every successful break-glass
  login.
- Add five seeded roles (`super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor`)
  bound to users via a new `role_bindings` table with deployment-wide / host-group / host
  scopes. Host-group and host scopes ship as schema only; only the deployment-wide scope
  is enforced in wave 1.
- Add a single authorization chokepoint that every UI/API handler calls before performing a
  privileged action. The engine is embedded OPA / Rego with policies baked into the binary
  at build time. Wave-1 has no existing deployments to migrate, so the chokepoint enforces
  from boot in the PR that converts the last privileged handler.
- Add an append-only audit log written on every authn outcome and every authz decision on a
  state-changing action. Dual-emit: durable row in MySQL + structured slog/OTel record on
  the active request span so existing SigNoz dashboards can alert on patterns. Reads of the
  audit log require `audit.read` and themselves write an audit-of-audit row.
- The product is a single-instance deployment (each customer runs their own server), so no
  tenant scaffolding column is added. Authorization scope is enforced through the role
  binding's `scope_type` enum, which today honours only the deployment-wide scope.
- Tighten session timeouts to security-console norms: 8h idle / 24h absolute for normal
  sessions, 15m idle / 1h absolute for break-glass. Destructive actions (host isolate,
  host kill_process, host run_script, critical-severity alert dismiss) require a fresh auth
  event within a 30-minute reauth window.
- **BREAKING** for the `/login` UI surface: replace the email + password form with a single
  "Continue with Okta" button. The local-password form now lives only at
  `/admin/break-glass`; it is not linked or hinted at from `/login`. The existing
  `POST /api/session` endpoint continues to work for break-glass authentication only.

## Capabilities

### New Capabilities

- `server-identity-authentication`: Server-side authentication flows - Okta OIDC discovery,
  authorize / callback, JIT provisioning, identity model (`users` ↔ `identities`),
  break-glass bootstrap token + WebAuthn registration, ongoing break-glass login at a
  separate path with IP allowlist + tighter rate limits, and the session augmentations
  (`identity_id`, `auth_method`, idle / absolute / reauth windows) that record how a session
  was authenticated. The session-cookie-and-CSRF surface itself stays in
  `ui-authentication-session`.
- `server-identity-authorization`: The RBAC engine plus the chokepoint every privileged
  handler funnels through. Owns the action registry, the role / role-binding / scope
  model, the seeded roles, and the OPA-evaluated decision shape (`allow`, `reason`).
- `server-identity-audit-log`: The append-only audit-event store, the `audit.Record(...)`
  surface every other capability calls into, the dual-emit to MySQL + slog / OTel, the
  decision-driven sampling (writes / destructive at 100%, reads tunable at 0% in MVP,
  break-glass actor forced to 100%), and the read endpoint behind `audit.read` that itself
  emits an audit-of-audit row.

### Modified Capabilities

- `ui-authentication-session`: The "login mints a session cookie" requirement and the
  argon2id password requirement now describe the break-glass-only path; OIDC sessions go
  through the new authentication capability and reach the session layer with
  `auth_method='oidc'`. The 12-hour expiry requirement is replaced by the new idle /
  absolute / reauth windows. The seeded-bootstrap requirement is rewritten around the
  single-use token + WebAuthn registration flow, so the recovery procedure changes.
- `web-ui`: The "anonymous user lands on the login page" and "successful login routes to
  the home view" scenarios change to describe the Okta-only `/login` page and the separate
  `/admin/break-glass` surface. The account menu adds the current role and the auth method.
- `server-admin-surface`: The "authenticated admin boundary" requirement is rewritten to
  describe the authorization chokepoint replacing the implicit "any authenticated user is
  admin" model; existing endpoints (enrollments, policy, attack-coverage, rules) gain
  per-action authz checks instead of a uniform admin gate. Adds user-management,
  role-binding, and audit-read endpoints under the same admin surface.

## Impact

**Tables added (identity context owns):** `identities`, `roles`, `role_bindings`,
`audit_events`, `bootstrap_tokens`, `webauthn_credentials`. Plus additive columns on
`users` (`display_name`, `status`, `is_breakglass`; `password_hash`/`password_salt` made
nullable) and `sessions` (`identity_id`, `auth_method`).

**Tables touched in other contexts:** none. The product is a single-instance deployment
so no tenant-partitioning column is added anywhere.

**New cross-context API surface (`server/identity/api/`):** `AuthZ.Allow(ctx, action,
resource) (Decision, error)`, `Audit.Record(ctx, event) error`, an `Actor` type populated
by session middleware and carried in `context.Context`, and a public action-name registry
so other contexts reference action constants instead of string literals. Every privileged
handler in `detection`, `rules`, `response`, and `endpoint` swaps its ad-hoc role check for
`identity.AuthZ.Allow(...)`.

**New configuration:** `auth.oidc.*`, `auth.breakglass.*`, `auth.session.*`, `authz.*`,
`audit.*` blocks plus two new env-derived secrets (`EDR_OIDC_CLIENT_SECRET`;
`EDR_SESSION_SIGNING_KEY` is reused for the OAuth state cookie). All secrets validated at
startup; missing values fail fast.

**New dependencies:** `github.com/coreos/go-oidc/v3/oidc`, `golang.org/x/oauth2`,
`github.com/open-policy-agent/opa/rego`, `github.com/go-webauthn/webauthn`. Argon2id and
the existing cookie signer are reused. The OPA module pulls in a sizable transitive tree;
flagged for dependency-review CI but accepted as a one-time cost.

**Rollback:** Schema changes are additive; existing deployments retain a working session
cookie + CSRF after the migration. The break-glass bootstrap-token flow is the only
behavior change for an existing operator: the migration auto-issues a token whose URL is
printed once on first start after upgrade, mirroring the current banner shape. Rollback to
pre-change is migration-down + redeploy of the prior server binary; the new identity tables
remain harmless if unused. The agent-server protocol and the events schema are
unchanged, so no agent-side rollback steps are required.
