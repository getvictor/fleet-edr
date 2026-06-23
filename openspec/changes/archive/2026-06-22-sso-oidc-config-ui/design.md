## Context

OIDC is configured today only through `EDR_OIDC_*` env vars, validated as a coherent block at boot (`server/config/config.go`, `loadOIDCConfig`/`enforceOIDCGate`). The OIDC provider client is built exactly once at startup in `server/identity/bootstrap/bootstrap.go:315` via `gooidc.NewProvider(ctx, issuer)` (a network discovery call), and the OIDC handler closes over that single immutable client. There is no persistence, no admin surface, and no way to change the IdP without editing env and restarting.

This change is the IdP-connection half of the wave-2 SSO + RBAC story. The RBAC halves (role-management UI #135, group-to-role mapping #136) and the other Admin settings sections (Users, Service accounts) are tracked separately and are out of scope here. The deployment is multi-replica and stateless (ADR-0010): durable cross-request state lives in MySQL; no shared in-process state may be required to serve the next request. The identity context is a bounded context (ADR-0004); cross-context callers reach it only through `server/identity/api`.

## Goals / Non-Goals

**Goals:**

- An admin configures OIDC end to end from the UI with no env edit and no restart, and a fresh user can SSO-login.
- Stored config in MySQL is the runtime source of truth, consistent across replicas; env vars become a first-boot bootstrap seed.
- The client secret is encrypted at rest and never returned to the browser after save.
- SSO config mutations funnel through the existing authz chokepoint (`sso.manage`) and are audited.

**Non-Goals:**

- OIDC group-to-role mapping / the `groups` scope (#136). Scopes stay read-only chips this wave.
- The Users and Service-accounts sections of Admin settings (#135 / #376), and any roles-matrix / custom-role editing.
- Moving user sessions off server-side rows, or any change to agent protocol, events schema, or the host token.
- Multi-IdP / multiple OIDC providers per deployment. The model stays one provider per deployment (singleton record).

## Decisions

### Decision: A singleton stored-config record in MySQL, owned by the identity context

A new table (e.g. `oidc_config`) holds one deployment-wide row (enforced by a fixed primary key / single-row constraint) with columns for issuer, client id, encrypted client secret, scopes, JIT enabled, default role, plus `config_version`, `updated_at`, and `updated_by`. The redirect URI is NOT a column: it is derived from the deployment external URL, which lives in a separate single-row versioned `app_config` JSON-document store (the scalable home for general, non-secret settings). The stores live behind new internal packages in `server/identity` and are exposed to the rest of the server only through the identity `api/` package, consistent with ADR-0004.

*Alternatives considered:* a generic key/value settings table (rejected: weaker typing/validation, and SSO is the only consumer this wave); a config file on disk (rejected: violates stateless multi-replica consistency, no transactional audit).

### Decision: Env bootstraps, DB governs (precedence)

On boot, if no row exists and the `EDR_OIDC_*` block is set, seed the row from env (reusing the existing validation in `config.go`). If a row exists, env is inert; log once at boot that env values are present but not applied. This keeps every existing env-only deployment working unchanged through the upgrade (the row is seeded on first boot from their env), then hands authority to the DB.

*Alternatives considered:* env always overrides (rejected: an admin's UI save would be silently reverted on the next restart, defeating the feature); DB always wins with no seed (rejected: breaks existing deployments on upgrade, which would boot with OIDC disabled).

### Decision: Rebuild the provider from stored config at runtime; per-replica cache keyed by issuer

Replace the boot-once client with a small provider resolver that, on the login/callback path, reads the current config and returns a `gooidc.Provider` + `oauth2.Config`. Because `NewProvider` does network discovery, cache the built provider per replica keyed by the config's identity (issuer + a version/`updated_at` stamp); rebuild when the stamp changes. The cache is a per-replica performance cache that is safe to lose (explicitly allowed under ADR-0010). No cross-replica signaling is needed: each replica notices the changed row on its next login attempt and rebuilds. This satisfies "no restart" without introducing shared in-process state.

*Alternatives considered:* rebuild on every request (rejected: a network discovery per login is too slow and hammers the IdP); in-process pub/sub to push config changes to replicas (rejected: adds shared-state machinery for no benefit; pull-on-use with a stamp is simpler and stateless-clean); store-and-restart (rejected: fails the issue's explicit no-restart acceptance).

### Decision: Encrypt the client secret at rest under an HKDF-derived key

Derive a dedicated symmetric key from `EDR_SECRET_KEY` via HKDF with a new domain-separation label (the codebase already derives the session-signing and host-token keys this way, `config.go:204`), and seal the client secret with an AEAD (AES-GCM) before storing. The read API returns only `secret_set: bool`; the update API accepts a new secret to rotate and leaves it untouched when the field is omitted. This matches the design's write-only contract and keeps the plaintext secret out of the DB and off the wire.

*Alternatives considered:* store plaintext and rely on DB-at-rest encryption (rejected: secret would still be returned by naive reads and visible to anyone with DB access; the product is a security tool and should not ship that); reuse `EDR_OIDC_CLIENT_SECRET` env as the only secret source and never store it (rejected: then rotation-from-UI is impossible, which is a core ask).

### Decision: New `sso.manage` action, granted to admin + super_admin

Register `sso.manage` in the action enumeration (`server/identity/api/authz.go`) and add it to the `admin` grant in the seeded role bundle (`super_admin` already covers it via its wildcard). The read and update/test endpoints all gate on `sso.manage` through the existing `HTTPGate` chokepoint, so they inherit the audit trail and reason codes for free. Mutations additionally emit an SSO-config audit row (actor user id + action, never the secret).

### Decision: HTTP surface under the operator-session + CSRF boundary

`GET /api/settings/sso` (read, returns config minus secret, plus `secret_set` and a connection-status hint), `PUT /api/settings/sso` (update; CSRF-checked; validates issuer URL, default role in {analyst, auditor} when JIT on), `POST /api/settings/sso/test-connection` (probe discovery + token endpoint of the submitted candidate or stored record; persists nothing). The default-role validation deliberately restricts to `analyst`/`auditor` so admin is never auto-granted from the JIT default (matches the design and the existing "never auto-elevate from a claim" posture).

### Decision: UI in a new Admin settings area, gated on the session permission set

Add the Admin settings shell + the Single sign-on page in `ui/src/`, reached from the account menu, gated on `sso.manage` appearing in the `/api/session` permission set via the existing `useCan()`/`Can` seam. Recreate the handoff design using Fleet's existing component library and design tokens (not the prototype HTML). Secret field is write-only (empty with a rotate affordance); scopes are read-only chips; default-role select offers Analyst/Auditor only; a break-glass-stays-available callout is shown.

## Risks / Trade-offs

- **A bad saved config locks operators out of SSO** → the break-glass account is always available (separate path, IP-allowlist gated) and is unaffected by OIDC config; the page surfaces this with a callout, and test-connection lets an admin validate before saving.
- **Per-replica cache serves a stale provider briefly after a change** → bounded to one login attempt per replica: the resolver checks the config stamp on use and rebuilds when it changed; worst case a single login redirect uses the prior issuer, never a security downgrade.
- **Rotating `EDR_SECRET_KEY` makes the stored secret undecryptable** → documented operational coupling (same as existing session/host-token derived keys); on a key change the admin re-enters the client secret via the rotate field. Call this out in `docs/okta-setup.md`.
- **Secret accidentally logged or returned** → enforced by tests: read responses and audit rows are asserted to contain no secret; the secret column is the only place the ciphertext lives.
- **Migration / rollback** → forward-only schema migration adds the table; rollback is a code revert plus dropping the table. Existing `EDR_OIDC_*` deployments re-seed on first boot, so revert restores env-only behavior with no data loss for them. No agent/protocol/schema/host-token surface is touched.

## Open Questions

- Connection-status semantics on read: compute a live probe on every `GET` (slower, always-fresh) vs. return last-known status stamped at save time. Leaning last-known + explicit test-connection button to avoid a per-page-load network call.
- Whether to also encrypt the client id (low sensitivity; current lean is no, only the secret is sealed).
- Exact table name and whether to fold future Admin-settings config (Users/Service-accounts wave) into the same package namespace now or let each capability own its store.
