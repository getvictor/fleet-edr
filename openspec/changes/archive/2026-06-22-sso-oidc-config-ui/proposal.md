## Why

Today an operator can only configure SSO by editing `EDR_OIDC_*` environment variables and restarting the server; `docs/okta-setup.md` documents the manual flow. Standing up or editing the IdP integration requires a deploy and an ops ticket, which pilot customers (and every commercial EDR they compare us to) do not expect. Operators expect to point the product at their IdP, test the connection, and save from an in-product admin screen, with the change taking effect without a restart and surviving across replicas.

## What Changes

- Persist the deployment's OIDC provider configuration durably in MySQL (issuer, client id, client secret, scopes, JIT-provisioning toggle, default JIT role) so it is the runtime source of truth and is consistent across replicas (ADR-0010). The redirect URI is derived from the deployment external URL (stored in a separate general settings document), not persisted as its own field.
- Establish precedence explicitly: `EDR_OIDC_*` env vars seed the stored config row on first boot when none exists; thereafter the stored row governs and env values are inert (logged once at boot, never silently applied). This keeps existing env-only deployments working unchanged on upgrade.
- Apply config changes at runtime without a restart: the OIDC provider/verifier is built from the stored config and rebuilt when the stored row changes, replacing today's boot-only `gooidc.NewProvider` wiring. Each replica refreshes from the durable row (per-replica cache, safe to lose).
- Store the client secret encrypted at rest under a key derived from `EDR_SECRET_KEY` (HKDF, matching the codebase's existing derived-key pattern). The secret is write-only over the API: it is accepted to rotate but never returned to the browser.
- Add a `GET`/`PUT` admin API for the OIDC config and a `test-connection` action (discovery-document fetch + token-endpoint reachability), gated behind a new `sso.manage` authorization action; every mutation emits an audit row.
- Add the **Single sign-on** admin settings page (the first section of the Admin settings area reached from the account menu, gated to `admin`/`super_admin`): provider form, write-only secret-rotate field, read-only redirect URL with copy, read-only scope chips, JIT toggle + default-role select (Analyst/Auditor only), test-connection button, break-glass-stays-available callout.
- Out of scope (deferred, deliberately): OIDC group-to-role mapping (#136), the Users and Service-accounts sections (#135 / #376), and any roles-matrix / custom-role editing.

## Capabilities

### New Capabilities

- `sso-configuration`: durable, runtime-reconfigurable OIDC provider configuration, its persistence and encryption-at-rest, the env-bootstrap precedence rule, the admin read/update/test-connection API gated on `sso.manage` with audit on mutation, and the admin Single sign-on settings page (write-only secret, no-restart apply).

### Modified Capabilities

- `server-identity-authentication`: the OIDC login path sources its provider configuration from the `sso-configuration` store rather than from env vars read once at boot; the provider is built and refreshed at runtime from the stored row, with env vars demoted to a first-boot bootstrap seed. JIT default role and requested scopes become runtime-editable through the stored config.
- `server-identity-authorization`: add `sso.manage` to the registered action enumeration, granted to `admin` and `super_admin`, so the SSO config endpoints funnel through the existing chokepoint like every other privileged action.

## Impact

- Code: `server/identity` (new stored-config package + migration, OIDC bootstrap rewired from boot-once to refresh-from-store in `server/identity/bootstrap/bootstrap.go` and `server/identity/internal/oidc/`), `server/identity/api/authz.go` (new action), `server/config/config.go` (env demoted to bootstrap seed), the audit pipeline (new mutation events), and the React UI (`ui/src/` new Admin settings area + Single sign-on page).
- Data: new MySQL table holding the singleton OIDC config row (encrypted secret column). Forward-only schema migration.
- APIs: new `/api/settings/sso` read/update and `/api/settings/sso/test-connection` routes under the operator-session + CSRF boundary.
- No change to the agent protocol, the events schema, or the persisted host token. Rollback is a code revert plus dropping the new table; deployments that set `EDR_OIDC_*` continue to work because the env block re-seeds the config on a fresh row.
