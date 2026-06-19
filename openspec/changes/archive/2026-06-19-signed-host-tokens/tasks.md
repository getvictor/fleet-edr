# Tasks

## 1. Signed token primitive

- [x] `server/endpoint/internal/signedtoken`: `Mint` / `Verify` for `v1.<payload>.<mac>`, HMAC-SHA256, claims `hid/ep/iat/exp/kid`, constant-time compare, kid check, expiry check.
- [x] PBT (pgregory.net/rapid) round-trip: `Verify ∘ Mint == identity` within the window; tamper, wrong-version, wrong-key, expired all rejected.

## 2. Revocation snapshot

- [x] `server/endpoint/internal/revocation`: per-replica `Snapshot` (`Allowed`, `Refresh`, `Run`), OTel size/age/refresh-failure instruments.
- [x] Store `RevocationEntries` (revoked OR epoch>0) + `BumpTokenEpoch` + `TokenStatus`.
- [x] Migration `00003_host_token_epoch.sql` adds `token_epoch`.
- [x] Unit tests: allowed/denied matrix, refresh retains previous on error.

## 3. Service + wiring

- [x] `VerifyToken` = signature + expiry + snapshot (no DB, no auto-rotate).
- [x] `Enroll` mints a signed token; `EnrollResponse.ExpiresAt` added.
- [x] `RefreshToken(ctx)` mints at the host's current epoch; `RotateToken` bumps epoch.
- [x] `POST /api/token/refresh` handler behind the host-token middleware; mounted in both server binaries.
- [x] Bootstrap derives the signing key (keyring `HostTokenSigningLabel`), builds signer + snapshot, starts the refresh loop in both binaries.
- [x] Config: `EDR_HOST_TOKEN_LIFETIME` default 60m.

## 4. Agent

- [x] Persist + parse `expires_at` in the token plist; decode it from enroll + refresh responses.
- [x] Proactive refresh loop (`Refresher`) at ~2/3 TTL via `POST /api/token/refresh`; 401 falls back to re-enroll.
- [x] HTTP/2 keep-alive PINGs on the shared agent transport.

## 5. Spec + tests + gates

- [x] Spec delta (this change) with MODIFIED / REMOVED / ADDED requirements.
- [x] Service + HTTP integration tests for verify / refresh / revoke-via-snapshot / epoch-bump.
- [x] `task lint:go` + `task lint:dashes` clean; server + agent tests green (default + integration tags).
- [x] Manual QA: dev server + agent on the edr-dev VM + SigNoz. Verified: enroll mints a `v1.` signed token + `expires_at` (persisted in the plist); authed polls verify with no SQL spans; clean proactive refresh ~1 min before expiry (3m TTL); operator epoch bump -> commander 401 -> auto re-enroll -> recovery; SigNoz shows `edr.auth.revocation_snapshot.size`/`.age_seconds` and dev-local traces.
- [ ] After merge: `openspec archive signed-host-tokens`.

## 6. Fast-follow (separate change)

- [ ] Remove the now-unused lower-level rotation store methods (`RotateHostToken`, `RotateHostTokenForce`, previous-token verify), the agent `rotate_token` command handler, and the vestigial `host_token_id` / `host_token_hash` / `EDR_HOST_TOKEN_GRACE`.
