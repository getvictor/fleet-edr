## Phase 1: schema + seeding (one PR per context, additive only)

- [ ] **1.1** Add identity-context tables to `server/identity/internal/store/schema.sql`:
  `tenants`, `identities`, `roles`, `role_bindings`, `audit_events`, `bootstrap_tokens`,
  `webauthn_credentials`. Plus additive columns on `users`
  (`tenant_id`, `display_name`, `status`, `is_breakglass`; nullable `password_hash`,
  `password_salt`) and `sessions` (`identity_id`, `auth_method`).
- [ ] **1.2** Add `tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'` to detection's
  `hosts` and `alerts` via `server/detection/internal/store/schema.sql`.
- [ ] **1.3** Add `tenant_id` to rules' `policies` via
  `server/rules/internal/store/schema.sql`.
- [ ] **1.4** Add `tenant_id` to response's `commands` via
  `server/response/internal/store/schema.sql`.
- [ ] **1.5** Add `tenant_id` to endpoint's `enrollments` via
  `server/endpoint/internal/store/schema.sql`.
- [ ] **1.6** Seed `tenants` with one row (`id='default'`, `status='active'`) on identity
  bootstrap; idempotent.
- [ ] **1.7** Seed the five built-in roles (`super_admin`, `admin`, `senior_analyst`,
  `analyst`, `auditor`) via `server/identity/internal/seed/roles.go`; idempotent.
- [ ] **1.8** Rewrite `server/identity/internal/seed/admin.go` →
  `seed/breakglass.go`: replace the printed-password flow with a single-use
  `bootstrap_tokens` row whose redemption URL is printed once on stderr. Migrate any
  existing `admin@fleet-edr.local` row to `is_breakglass=1` with NULL password fields
  and auto-issue a token.
- [ ] **1.9** Per-context integration tests at
  `server/identity/internal/tests/schema_test.go` and the parallel test file in each
  other context that touched its `tenant_id` column. Verify defaults, NULL allowance,
  and that wave-1 reads do not query on `tenant_id`.
- [ ] **1.10** Cross-context integration test at
  `test/integration/tenant_scaffolding_test.go` — boot the full server, exercise
  every existing read endpoint, assert the rendered SQL never contains `tenant_id` in
  a WHERE clause.

## Phase 2: authorization chokepoint shipped in shadow mode

- [ ] **2.1** New package `server/identity/internal/authz/` with the OPA engine wiring
  (compiled `PreparedEvalQuery`, `embed`-baked `*.rego` files at
  `internal/authz/policy/*.rego`, SIGHUP reload).
- [ ] **2.2** Action registry at `server/identity/api/actions.go` (typed `Action`
  constants) and `server/identity/internal/authz/policy/data/actions.json`. Build-time
  parity check that the two lists agree.
- [ ] **2.3** Public surface exports on `server/identity/api/`: `Actor`,
  `RoleBinding`, `Resource`, `Decision`, `AuthZ` interface, `ActorFromContext(ctx)`.
- [ ] **2.4** Session middleware in `server/identity/internal/sessions/` builds the
  `Actor` from the session row + role bindings + tenant id; threads it into request
  context.
- [ ] **2.5** Bench harness at `server/identity/internal/authz/bench_test.go` covering
  allow + deny paths over the seeded roles. Wire into CI; fail at p99 ≥ 1ms.
- [ ] **2.6** Add `authz.shadow_mode` config flag (default `false` for fresh deployments,
  `true` for upgrades). Engine returns `{allow:true, reason:"shadow_mode"}` when set;
  audit row records the would-be decision and notes shadow mode in payload.
- [ ] **2.7** Convert every privileged handler in detection / rules / response /
  endpoint / identity to call `authz.Allow(ctx, action, resource)`. One PR per context.
  Remove any ad-hoc role checks the call replaces. arch-go must continue to pass.
- [ ] **2.8** Code-search rule: privileged-route registration that does not call
  `authz.Allow` fails the build. Add to lefthook + CI.

## Phase 3: audit recorder + dual-emit

- [ ] **3.1** New package `server/identity/internal/audit/` with `Recorder` (DB
  insert + slog + OTel span attributes). Public `Audit` interface on
  `server/identity/api/`.
- [ ] **3.2** Async writer with a bounded buffer; back-pressure logs to slog/OTel only.
  Pattern mirrors detection's event-ingest queue.
- [ ] **3.3** Wire `audit.Record` into the authz chokepoint so every decision lands an
  audit row (subject to read-sampling). Wire it into authentication outcomes.
- [ ] **3.4** Add `audit.read_sampling` config (default 0.0); break-glass actor forces
  1.0 regardless.
- [ ] **3.5** New endpoint `GET /api/audit-events` in identity's admin handlers; gated
  on `audit.read`; itself emits an audit-of-audit row. Pagination via cursor.
- [ ] **3.6** Static-analysis check: no production code path may emit
  `UPDATE audit_events` or `DELETE FROM audit_events`. Add to lefthook.

## Phase 4: OIDC + break-glass authentication

- [ ] **4.1** New package `server/identity/internal/oidc/` using
  `github.com/coreos/go-oidc/v3/oidc` + `golang.org/x/oauth2`. Discovery, JWKS refresh,
  PKCE S256, ID-token verification (issuer, audience, expiry, nonce), ±2-minute clock
  skew tolerance.
- [ ] **4.2** New routes in identity's bootstrap: `GET /api/auth/login`,
  `GET /api/auth/callback`. State stored in a short-lived signed cookie reusing
  `EDR_SESSION_SIGNING_KEY`.
- [ ] **4.3** JIT provisioning: insert `users` (NULL password) + `identities`
  (provider, subject), bind to `analyst` at tenant scope, audit `user.created`. Honors
  `auth.oidc.allow_jit_provisioning`.
- [ ] **4.4** New package `server/identity/internal/breakglass/` covering bootstrap
  token issuance + redemption, password length validation (≥ 12 characters), WebAuthn
  registration via `github.com/go-webauthn/webauthn`. Atomic redemption + user
  creation + credential persistence. Wave-1 password policy is length-only (CIS
  guidance for MFA-protected accounts: 8+ chars; we land at 12); zxcvbn entropy
  scoring is wave-2 polish.
- [ ] **4.5** New routes: `GET /admin/break-glass`, `POST /admin/break-glass` (login
  with password + WebAuthn assertion), `GET /admin/break-glass/setup`,
  `POST /admin/break-glass/setup`. IP allowlist 404 enforcement when configured.
- [ ] **4.6** Tighter rate limits on the break-glass surface (per-IP + per-email +
  bootstrap-setup bucket). Existing rate-limiter middleware extended.
- [ ] **4.7** UI: replace the `/login` form with the "Continue with Okta" page; add the
  `/admin/break-glass` and `/admin/break-glass/setup` views. Wire account-menu to
  surface role + auth method.
- [ ] **4.8** Per-context integration tests for OIDC happy path, JIT provisioning,
  unknown-subject deny, expired state, bootstrap-token redemption, expired token,
  consumed token, IP allowlist 404, rate-limit responses.

## Phase 5: session middleware updates

- [ ] **5.1** Replace flat 12-hour expiry with idle (8h) + absolute (24h) for normal
  sessions; idle (15m) + absolute (1h) for break-glass.
- [ ] **5.2** Reauth window (30m) enforcement on the action set (host.isolate,
  host.kill_process, host.run_script, alert.dismiss with severity=critical). Typed
  `reauth_required` error.
- [ ] **5.3** UI: handle `reauth_required` by prompting the operator to re-authenticate
  inline, then retrying the original action.
- [ ] **5.4** Per-context integration tests for each timeout window and the reauth
  challenge.

## Phase 6: shadow-mode flip

- [ ] **6.1** Operator playbook: review the shadow-mode dashboard for one full week of
  production traffic on the pilot deployment; deny-decision count must read zero on
  every privileged handler. Resolve any outliers.
- [ ] **6.2** Single-PR change: flip `authz.shadow_mode` default to `false` for fresh
  deployments and provide a release note advising upgrade-path operators to flip the
  same flag once their dashboard is clean.
- [ ] **6.3** Remove the upgrade-default branch from the config loader once all
  customer deployments have flipped (tracked separately, not blocking this change).

## Phase 7: documentation

- [ ] **7.1** Operator runbook: break-glass redemption + WebAuthn registration,
  break-glass credential rotation, lost-credential recovery procedure.
- [ ] **7.2** Okta tenant setup guide: app type (web), redirect URLs, scope set,
  group claim posture (group → role mapping deferred to wave 2).
- [ ] **7.3** Role + permission matrix: machine-readable copy under
  `server/identity/internal/authz/policy/data/actions.json` plus a human-readable
  rendering in `docs/`.
- [ ] **7.4** SigNoz dashboard wiring: deny-decision rate by handler, break-glass
  login rate, bootstrap-token issuance count, audit-write-failure count.
- [ ] **7.5** Update `docs/threat-model.md` to reflect the new identity boundary,
  the chokepoint, the audit log, and the WebAuthn-mandatory break-glass control.

## Phase 8: validation gates (run continuously, not a separate phase)

- [ ] **8.1** arch-go (`arch-go.yml` + `test/arch/arch_test.go`) passes at every PR
  boundary.
- [ ] **8.2** Coverage on new code remains ≥ 80% on the SonarCloud gate (per
  CLAUDE.md).
- [ ] **8.3** Cross-context integration tests at `test/integration/` cover at least
  one end-to-end scenario per phase: SSO login → host.isolate (denied for analyst,
  allowed for senior_analyst) → audit row visible to auditor.
- [ ] **8.4** Property-based tests where the shape fits: scope-resolution invariants,
  role-binding expiry behavior, action-registry parity.
