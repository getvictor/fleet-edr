## 1. Persistence and credential

- [x] 1.1 Add forward-only MySQL migration(s): a `service_accounts` table (id, client_id, name, role, created_by, expires_at, enabled, epoch, last_used_at, created_at) and a credential store holding the client id + `SHA-256(secret)`, never plaintext; index by client id for the token-endpoint lookup
- [x] 1.2 Add a new `server/identity/internal/serviceaccounts` package owning the tables: create / list / rotate / revoke, epoch bump on revoke/disable, constant-time hash comparison; expose cross-context surface only through `server/identity/api` (do not create a parallel identity context)
- [x] 1.3 Reserve and use the `api_token` identity kind for the service-account principal; bind exactly one seeded role, and reject `admin`/`super_admin` and any role granting the console-management actions (`service_account.*`, `user.*`, `sso.manage`) so a service account cannot mint or escalate other service accounts

## 2. Token issuance and signing

- [x] 2.1 Add the keyring label `edr/service-account-token/sign/v1` in `internal/keyring`; derive the HMAC signing key from `EDR_SECRET_KEY`
- [x] 2.2 Generalize / reuse `signedtoken` to mint the access token with claims: subject (service-account id), `aud` (deployment), role/scope, `iat`, `exp` (15 min), `kid`, `jti`
- [x] 2.3 Implement `POST /api/token` (client-credentials grant): validate the presented credential (enabled, unexpired, hash match), refuse invalid/disabled/revoked/expired without issuing; return `{access_token, token_type: "Bearer", expires_in}`; no refresh token; rate-limit the endpoint
- [x] 2.4 PBT round-trip / unit tests: sign then verify is identity; tampered signature, expired `exp`, and wrong `aud` all fail; a wrong key fails to verify

## 3. Stateless verification and revocation

- [x] 3.1 Add bearer middleware on the API mux that validates the access token locally (signature + `exp` + `aud`) with no per-request DB read and resolves the service-account principal onto the request context
- [x] 3.2 Add the per-replica epoch snapshot (reuse the #454 host-token revocation pattern): refresh `{service_account_id -> epoch, revoked_at}` from MySQL on a short fixed interval (≈5 seconds, matching the #454 host-token snapshot cadence); reject a token whose epoch is stale; document the cache as per-replica, safe to lose (ADR-0010)
- [x] 3.3 Test: a revoked service account cannot mint a new token immediately, and an outstanding token stops validating within the refresh window with no restart

## 4. Authorization and audit

- [x] 4.1 Register `service_account.read/create/rotate/revoke` in `server/identity/api/authz.go` and the `policy/data/actions.json` mirror; grant to `admin` (super_admin via wildcard); update the parity check expectations
- [x] 4.2 Resolve a service-account access token to an `Actor` carrying the bound role; ensure the actor is never `SessionFresh` and that the reauth freshness gate does not apply to it (destructive actions allowed only when the bound role grants them)
- [x] 4.3 Emit audit rows on create / rotate / revoke and on every token issuance, recording the actor and service account; never record the secret or the token
- [x] 4.4 Tests: admin/super_admin allowed for management actions, analyst/auditor denied with no-matching-rule; a service-account actor with a role granting `host.isolate` is allowed without freshness; one without it is denied; audit rows assert no secret/token

## 5. Admin API and UI

- [x] 5.1 Management routes under operator-session + CSRF + `service_account.*`: `GET /api/settings/service-accounts` (list, no secrets), `POST` (create, secret shown once), `POST /{id}/rotate` (new secret shown once), `DELETE /{id}` (revoke)
- [x] 5.2 Wire every existing API route to accept the bearer access token as a second authenticator alongside the session cookie via a shared actor-resolution step; the bearer boundary is CSRF-exempt
- [ ] 5.3 Add the Service-accounts admin settings page in `ui/src/` (list with name/role/created/last-used/state, create-with-one-time-secret, rotate, revoke), gated on the management actions via the `useCan()`/`RequirePermission` seam; add the API client calls (CSRF on mutation)
- [ ] 5.4 Vitest unit + component tests: page hidden without the grant; the one-time secret is shown on create/rotate and never re-fetched; revoke confirms

## 6. Docs and spec traceability

- [x] 6.1 Add a docs section on creating and using a service account (obtain a token via the client-credentials grant, present it as a bearer token, rotate/revoke), and the env-vs-stored, TTL, and revocation-window semantics
- [x] 6.2 Add spectrace markers tying tests to the new `server-identity-service-accounts` scenarios and the modified authentication/authorization scenarios
- [x] 6.3 Run `openspec validate service-account-auth --strict` and the no-emdash/dash + markdown-prose linters; fix any findings
- [ ] 6.4 Mark ADR-0013 Accepted once this change merges
