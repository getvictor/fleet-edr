# Remove the EDR_OIDC_* env-var seeding path now that SSO is configured via the UI/API

## Why

OIDC/SSO is now fully configurable at runtime through the **Admin settings -> Single sign-on** page backed by the durable `oidc_config` store and the audited admin API (#375). The stored config is the source of truth, survives restarts, supports test-connection before save, and applies without a restart. That makes the original environment-variable configuration path redundant: the server still reads and enforces `EDR_OIDC_*`, seeds the store from them on first boot, and refuses to boot without them unless `EDR_AUTH_ALLOW_NO_OIDC=1`. Under UI-only configuration the server must always boot before any OIDC config exists (the admin signs in via break-glass and configures it), so the env-var boot gate no longer protects anything: the quickstart already defaults the opt-out flag to `1`, making it effectively always-on.

This change removes the dead env-var ingestion and the first-boot seeding path, drops the `EDR_AUTH_ALLOW_NO_OIDC` gate in favor of always-boot, and replaces the demo/QA stacks' reliance on server-side env-seeding with an explicit, programmatic seed in the demo seeder. The durable store, admin API, and UI page (the replacement) are untouched.

## What changes

- **Removed server env vars (7), now unsupported (inert if set):** `EDR_OIDC_ISSUER`, `EDR_OIDC_CLIENT_ID`, `EDR_OIDC_CLIENT_SECRET` (+ `_FILE`), `EDR_OIDC_REDIRECT_URL`, `EDR_OIDC_ALLOW_JIT_PROVISIONING`, `EDR_OIDC_DEFAULT_ROLE`, and `EDR_AUTH_ALLOW_NO_OIDC`. The matching `Config` fields, `loadOIDCConfig` / `parseOIDCOverrides` / `enforceOIDCGate`, and the role-allowlist cross-check are deleted.
- **First-boot seeding deleted.** `seedOIDCConfigFromEnv`, the `oidcSeed` field, and the connection-config fields of `OIDCDeps` (the env-to-store plumbing) are removed. `OIDCDeps` keeps only the live deployment knobs the handler needs (`StateCookieTTL`, `HTTPClient`).
- **Always-boot is the default posture.** With no env gate, the server always boots. The break-glass surface (the bootstrap login path) defaults to its localhost dev configuration when no `EDR_BREAKGLASS_*` is set, instead of being suppressed when OIDC was env-configured. The fail-closed signal `OIDCEnabled` is derived from the `oidc_config` store rather than from an env var.
- **Demo/QA seed the store programmatically.** A new public `bootstrap.SeedOIDCConfig` seam writes a connection config (sealing the client secret with the deployment OIDC sealer key) directly to the store, idempotently, never clobbering a later UI edit. The `fleet-edr-demo-seed` one-shot calls it so the demo's dex SSO still auto-configures on the source-built / v0.4.0+ image; `task dev:server:qa-oidc` and the e2e coverage run seed via the same seam.
- **Compose backward-compatibility (transitional).** `docker-compose.demo.yml` floats to the released `:latest` image (docs/doc-versioning.md), so it must boot the v0.3.0 server too. The server-side `EDR_OIDC_*` stay in the demo (v0.3.0 env-seeds them; the v0.4.0+ server ignores them and the seeder configures SSO) and `docker-compose.quickstart.yml` keeps `EDR_AUTH_ALLOW_NO_OIDC` (v0.3.0 needs it to boot break-glass-only; v0.4.0+ ignores it). Both blocks are marked TRANSITIONAL and removed once `:latest` is v0.4.0+.
- **A removed variable is inert.** Setting one is ignored at boot rather than an error, so a stale deployment config does not take a deployment down. Existing env-only deployments already had their config persisted to `oidc_config` on first boot under #375, so removal does not strand them.

## Out of scope

The durable store, admin API, and UI page stay: they are the replacement. No change to the stored configuration's shape, the login flow, or JIT semantics beyond removing the env override.

## Migration note

Existing deployments that relied on env-seeding already had their config persisted to the `oidc_config` store on first boot (#375), so removal does not strand them. Operators who still set `EDR_OIDC_*` or `EDR_AUTH_ALLOW_NO_OIDC` will find them silently ignored; configure SSO under **Admin settings -> Single sign-on**. Called out in the changelog.
