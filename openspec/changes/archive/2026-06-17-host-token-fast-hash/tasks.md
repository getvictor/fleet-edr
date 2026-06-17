# Verify host tokens with a fast keyed hash, not argon2id: tasks

## 1. Crypto primitives

- [x] `server/endpoint/internal/mysql/hash.go`: replaced argon2id with keyed HMAC-SHA256. `hashToken(pepper, token) []byte` returns `HMAC-SHA256(pepper, token)`; `verifyToken(pepper, token, want) bool` recomputes and compares with `hmac.Equal` (constant-time). Dropped the `salt` return/param.
- [x] Removed the package-level `argonTime` / `argonMemory` / `argonThreads` vars and the `init()` test-cost override (the issue #170 workaround); dropped the `golang.org/x/crypto/argon2`, `crypto/subtle`, and `testing` imports.
- [x] Kept `generateToken` (32-byte `crypto/rand`) and `tokenID` (SHA-256 lookup key) unchanged. Scrubbed the argon2id references in the file header and `doc.go`.

## 2. Store wiring

- [x] `server/endpoint/internal/mysql/store.go`: threaded the pepper into `Store` (`pepper []byte` field; `NewStore(db, pepper)`). `Register`, `RotateHostToken`, `RotateHostTokenForce` store only `host_token_hash = HMAC(s.pepper, token)` (no salt); `verifyAgainstCurrent` / `verifyAgainstPrevious` call `verifyToken(s.pepper, token, row.Hash)`. Removed every `host_token_salt` / `previous_host_token_salt` read and write, and the now-stale argon2id/salt comments.
- [x] `server/endpoint/bootstrap/bootstrap.go`: added `Deps.HostTokenPepper []byte`, validated `>= 32` bytes in `New`, passed it to `mysql.NewStore`.

## 3. Schema

- [x] `server/endpoint/migrations/00002_drop_host_token_salt.sql`: `ALTER TABLE enrollments DROP COLUMN host_token_salt, DROP COLUMN previous_host_token_salt`. No data migration; pre-existing argon2id hashes in `host_token_hash` stop verifying (breaking re-enroll, by design). The new migration's comment documents the supersession; `00001_initial.sql` is left as the historical baseline.

## 4. Root key + key derivation (folds in EDR_SESSION_SIGNING_KEY)

- [x] New `internal/keyring/` package: `New(root []byte) (*Keyring, error)` (rejects `< 32` bytes, clones the root) and `Derive(label string) []byte` via `crypto/hkdf` HKDF-SHA256. Unit tests cover determinism per label, independence across labels/roots, and root-copy isolation.
- [x] `server/config/config.go`: added `SecretKey []byte` + `loadSecretKey` (required, `>= 32` bytes, unconditional, `*_FILE` fallback via the existing `FileBackedGetenv` wrapper). Removed the `SessionSigningKey` field, its `EDR_SESSION_SIGNING_KEY` read in `loadOIDCConfig`, the OIDC-gated length check in `enforceOIDCGate`, and the now-unused `oidcSigningKeyMinBytes` const.
- [x] `server/cmd/fleet-edr-server/main.go`: build the keyring from `cfg.SecretKey` in `openContexts`; pass `kr.Derive("edr/session/signing/v1")` into `openIdentity` (the identity bootstrap `SessionSigningKey` dep) and `kr.Derive("edr/host-token/pepper/v1")` into `openEndpoint` (the endpoint `HostTokenPepper` dep). Labels are package consts.
- [x] `render.yaml`: replaced `EDR_SESSION_SIGNING_KEY` with `EDR_SECRET_KEY` (`generateValue: true`).
- [x] Other env surfaces: `Taskfile.yml` (`dev:server` + `dev:server:qa-oidc`), `docker-compose.demo.yml`, `packaging/docker-compose-multi-replica.yml` (`EDR_SECRET_KEY_FILE` + the `secrets:` block + secret filename), `scripts/test-e2e-coverage.sh`.
- [x] Docs: `docs/operations.md` (renamed the section to "EDR root secret", rewrote the rotation runbook to include the fleet-wide re-enroll), `docs/install-server.md` (config table row + multi-replica secret), `docs/okta-setup.md`, `docs/threat-model.md`, `docs/breakglass.md`, and the `operations.md#edr-root-secret` cross-links.

## 5. Spec

- [x] `agent-enrollment` delta: ADDED "Host tokens are stored and verified with a fast keyed hash" with scenarios for issuance storage, hot-path verification, mismatch rejection, and the breaking re-enroll of pre-existing argon2id tokens.
- [x] `server-identity-authentication` delta: ADDED "Pre-auth cookie signing keys derive from the deployment root secret" capturing the `EDR_SECRET_KEY` root, the removal of `EDR_SESSION_SIGNING_KEY`, and the always-required boot gate.

## 6. Tests

- [x] `server/endpoint/internal/mysql/internal_test.go`: HMAC round-trip (token verifies, wrong token / wrong pepper / empty hash do not) + a `pgregory.net/rapid` property test over random tokens + peppers.
- [x] `server/endpoint/internal/mysql/store_test.go` + `server/endpoint/internal/service/rotation_test.go`: thread a fixed test pepper through `NewStore`; enroll-then-verify and rotate-then-verify still pass against real MySQL (these also exercise the new migration via `testkit.ApplySchema`).
- [x] `test/integration/setup.go`: supply `HostTokenPepper` to the endpoint bootstrap.
- [x] `server/config/config_test.go`: `envMap` defaults `EDR_SECRET_KEY` (empty-string opt-out); removed the obsolete OIDC session-key cases; added `EDR_SECRET_KEY` missing + short negative cases.

## 7. Verification

- [x] `go test ./server/... ./internal/...` green (full suite, incl. DB-backed endpoint/identity tests).
- [x] `go test -tags integration ./test/integration/...` green.
- [x] `task lint:go` (exit 0), gofmt clean, `task lint:dashes` clean, `task lint:md` + `task lint:md:prose` clean on touched files.
- [x] `openspec validate host-token-fast-hash --strict` valid; `spectrace check` resolves the 4 new scenario markers (0 invalid references).
- [x] Live dev-server + VM + SigNoz smoke: dev server booted on the new required `EDR_SECRET_KEY`; the edr-dev VM agent (192.168.64.5) hit a `401 invalid_token` on its pre-change token then re-enrolled automatically (breaking re-enroll confirmed live); 20 authed `GET /api/commands` returned 200 in 4.6-11.4ms; SigNoz (`deployment.environment=dev-hmac-qa`) shows p99 15ms and a trace with no ~235ms argon2id gap (auth is now the `enrollments` SELECT + ~50us HMAC).
