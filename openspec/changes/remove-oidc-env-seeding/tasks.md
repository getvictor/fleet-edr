# Tasks

## Server config

- [x] Delete the OIDC `Config` fields, `AuthAllowNoOIDC`, `loadOIDCConfig`, `parseOIDCOverrides`, `enforceOIDCGate`, `appendIfMissing`, `builtinRoleIDs`, the `loadOIDCConfig` call, and the `OIDCAllowJITProvisioning` default in `server/config/config.go`. Keep `DefaultOIDCScopes` + `DefaultOIDCStateCookieTTL`.
- [x] Scrub `server/config/config_test.go`: drop `TestLoad_OIDCConfig` and every `EDR_OIDC_*` / `EDR_AUTH_ALLOW_NO_OIDC` key and assertion; keep `TestDefaultOIDCScopes`.

## Identity bootstrap

- [x] Remove `seedOIDCConfigFromEnv`, the `oidcSeed` field, `oidcConfiguredAtBoot`, and the env-to-store fields of `OIDCDeps` (keep `StateCookieTTL`, `HTTPClient`).
- [x] Make `OIDCEnabled(ctx)` derive from the `oidc_config` store; rework `buildBreakglass` to drop the `OIDC.Issuer` guard so break-glass always mounts (always-boot).
- [x] Add public `bootstrap.SeedOIDCConfig(ctx, db, oidcSecretKey, OIDCSeedInput)` that seals the secret + writes `oidc_config` and the external URL, idempotent (no-op when a row exists, unless `Force`).

## Wiring

- [x] Update `server/cmd/fleet-edr-server/main.go` to drop `cfg.OIDC*` + `DefaultOIDCScopes` from the `OIDCDeps`, passing only `StateCookieTTL`.
- [x] Demo seeder (`server/cmd/fleet-edr-demo-seed`): add OIDC + root-secret config fields, an `--oidc-only` mode, and `--oidc-force`; call `bootstrap.SeedOIDCConfig` (deriving the sealer key from `EDR_SECRET_KEY`).
- [x] `docker-compose.demo.yml`: add `EDR_DEMO_OIDC_*` + `EDR_SECRET_KEY` to the seeder; keep the server-side `EDR_OIDC_*` (TRANSITIONAL, for the released `:latest` v0.3.0 image the demo floats to). Keep `EDR_AUTH_ALLOW_NO_OIDC` in `docker-compose.quickstart.yml` for the same reason (TRANSITIONAL). Drop it from `Taskfile` `dev:server` (always source-built, no compat need).
- [x] Rework `dev:server:qa-oidc` to migrate + seed-oidc + run; rework `scripts/test-e2e-coverage.sh` to seed per phase via `--oidc-only --oidc-force`.

## Tests, docs, spec

- [x] Delete `oidc_seed_test.go`; rework the SSO admin integration helper to seed via `SeedOIDCConfig`/the store; add `sso_seed_test.go` with a restart-survival + idempotency + force test (covers the `stored-configuration-survives-a-restart` scenario).
- [x] Update docs (`okta-setup.md`, `install-server.md`, `quickstart-vm.md`, `qa-rc-vm-runbook.md`, `threat-model.md`), dex configs, `.coderabbit.yaml`, the e2e package note + jit-disabled spec comment, and `oidc/doc.go`; add a `CHANGELOG.md` entry with the migration note.
- [x] `go build ./...`, `task lint:go` (0 issues), config + identity + cmd tests pass, `openspec validate --all --strict` (33/33), `tools/spectrace check --strict` (100%), dash + md-prose lint, compose YAML validate.
- [x] Manually verified: `task qa:up` + reworked `dev:server:qa-oidc` boots with no `EDR_OIDC_*` / `EDR_AUTH_ALLOW_NO_OIDC`, prints the break-glass token, and a full browser SSO sign-in via dex (`analyst@qa.local`) JIT-provisions and lands on the dashboard (token exchange decrypts the seeded secret).
