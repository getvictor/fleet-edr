## 1. Persistence and encryption

- [x] 1.1 Add a forward-only MySQL migration creating a single-row `oidc_config` table (issuer, client_id, client_secret_enc, redirect_url, scopes, jit_enabled, default_role, updated_at, updated_by) with a single-row constraint
- [x] 1.2 Add a new internal package in `server/identity` owning the table: typed Get/Upsert plus a config-version/stamp (use `updated_at` or a version column) for cache invalidation
- [x] 1.3 Derive a dedicated AEAD key from `EDR_SECRET_KEY` via HKDF under a new domain-separation label (alongside the existing session/host-token derivations in `config.go`); seal/open the client secret with AES-GCM
- [x] 1.4 PBT round-trip test: `Open ∘ Seal == identity` for the secret; assert ciphertext differs from plaintext and a wrong key fails to open

## 2. Bootstrap precedence (env seeds, DB governs)

- [x] 2.1 On boot, when no `oidc_config` row exists and the `EDR_OIDC_*` block is set, seed the row from env (reuse the existing validation in `loadOIDCConfig`/`enforceOIDCGate`)
- [x] 2.2 When a row exists, do not apply env; log once that env values are present but inert
- [x] 2.3 Tests: first-boot seeds the row from env; existing row makes a differing `EDR_OIDC_ISSUER` inert

## 3. Runtime provider resolver (no restart)

- [x] 3.1 Replace the boot-once `gooidc.NewProvider` wiring in `server/identity/bootstrap/bootstrap.go` with a resolver that reads the stored config on the login/callback path and returns a provider + `oauth2.Config`
- [x] 3.2 Add a per-replica cache keyed by (issuer, config stamp); rebuild on stamp change; document it as a safe-to-lose per-replica perf cache (ADR-0010)
- [x] 3.3 Update the OIDC handler so login/callback use the resolver result rather than a captured client
- [x] 3.4 Test: updating the stored issuer makes the next `GET /api/auth/login` redirect to the new issuer with no restart

## 4. Authorization and audit

- [x] 4.1 Register the `sso.manage` action in `server/identity/api/authz.go`
- [x] 4.2 Add `sso.manage` to the seeded `admin` role bundle (super_admin already covers it via wildcard); update the role seed + the authz Rego/data
- [x] 4.3 Emit an SSO-config mutation audit row (actor user id + action, never the secret) on create/update/rotate
- [x] 4.4 Tests: admin/super_admin allowed, analyst/senior_analyst/auditor denied with `no_matching_rule`; audit row asserted to contain no secret

## 5. Admin API

- [x] 5.1 `GET /api/settings/sso` behind operator-session + `sso.manage`: return config minus secret, plus `secret_set` and a connection-status hint
- [x] 5.2 `PUT /api/settings/sso` behind operator-session + CSRF + `sso.manage`: validate (issuer URL syntactically valid; default role in {analyst, auditor} when JIT enabled), rotate secret only when provided, persist + audit
- [x] 5.3 `POST /api/settings/sso/test-connection` behind `sso.manage`: fetch discovery doc + confirm token endpoint reachable for the submitted candidate (or stored record); persist nothing; return pass/fail + reason
- [x] 5.4 Wire the routes through the identity bootstrap mux registration; expose any cross-context surface via `server/identity/api` only
- [x] 5.5 Handler tests: read omits secret; update rejects default role `admin`; unauthorized caller gets 403; test-connection persists nothing

## 6. UI: Admin settings shell + Single sign-on page

- [ ] 6.1 Add the Admin settings area shell (account-menu entry + sub-nav) in `ui/src/`, gated on `sso.manage` via the existing `useCan()`/`Can` seam and the `/api/session` permission set
- [ ] 6.2 Build the Single sign-on page using Fleet's existing component library + design tokens (do not port the prototype HTML): provider form, read-only redirect URL with copy, read-only scope chips, write-only secret-rotate field, JIT toggle, default-role select (Analyst/Auditor only), connection-status pill, test-connection button, break-glass callout
- [ ] 6.3 Add the API client calls (read/update/test-connection) in `ui/src/`, sending CSRF on mutation; secret omitted from the form unless the admin enters a new value
- [ ] 6.4 Vitest unit + component tests: page hidden without `sso.manage`; secret field never prefilled; save sends only changed fields; test-connection surfaces success/failure

## 7. Docs and spec traceability

- [ ] 7.1 Update `docs/okta-setup.md`: configuration now lives in the UI; document the env-seeds-DB-governs precedence and the `EDR_SECRET_KEY`-rotation coupling for the stored secret
- [ ] 7.2 Add spectrace markers tying tests to the new `sso-configuration` scenarios and the modified authentication/authorization scenarios
- [ ] 7.3 Run `openspec validate sso-oidc-config-ui --strict` and the no-emdash/dash + markdown-prose linters; fix any findings
