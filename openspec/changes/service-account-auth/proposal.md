## Why

The product has no way for a non-human principal (automation, CI/release pipelines, AI agents) to call the EDR API. Today every authenticated caller is a human operator holding a browser session cookie; there is no programmatic credential. Issue #376 ("Support API-only users") is the first concrete need, and the SSO config work (#375) deferred the Service-accounts section of Admin settings to here.

The naive answer (a long-lived static API key) is an industry-recognized anti-pattern for proliferating agents: such keys are rarely scoped, easily leaked, and hard to revoke or audit at scale. The constraint we set in #375 was "one credential model, two transports": a service account must resolve to the same `Actor` + permission set, through the same authorization chokepoint, as a human operator, over `Authorization: Bearer` instead of a cookie. ADR-0013 records the resulting decision: the OAuth 2.1 client-credentials grant exchanging a long-lived hashed credential for a short-lived, self-validating signed access token, generalizing the #454 host-token machinery so the API hot path stays stateless (ADR-0010) as the agent population grows.

## What Changes

- Introduce a **service-account principal**: an `identities` row with provider kind `api_token` (the reserved kind), bound to a user-less principal and a single role (never `super_admin`). A service account has a display name, an owning creator, a role, an optional expiry, and an enabled/revoked state.
- Issue each service account a **client credential** (`client_id` + secret). The secret carries a self-describing prefix + checksum, is stored **hashed** at rest (SHA-256, as sessions already are), is shown exactly once at creation/rotation, and is never re-displayed. The credential carries a mandatory, configurable maximum lifetime.
- Add a **token endpoint** (`POST /api/token`, OAuth 2.1 client-credentials grant): a service account presents its credential and receives a short-lived (15 minute) signed access token. The token reuses the `signedtoken` machinery under a new keyring label `edr/service-account-token/sign/v1`, carrying subject (service-account id), audience (this deployment), role/scope, `iat`, `exp`, `kid`, and `jti`. There is no refresh token; the client re-runs the grant near expiry.
- **Validate the access token statelessly on the API request path**: signature + `exp` + `aud` checked locally on every request with no DB read, exactly as host tokens are. The bearer-authenticated API boundary is CSRF-exempt (a bearer token is not an ambient credential). The verified token resolves to an `Actor` carrying the service account's role, funneled through the existing authz chokepoint.
- **Revoke via short TTL + a per-replica epoch snapshot**: disabling or revoking a service account bumps its epoch; each replica refreshes the epoch snapshot from MySQL every few seconds (the host-token mechanism, generalized), so outstanding tokens stop validating within the refresh window without a per-request lookup, and no new token can be minted because the credential is gone.
- Add an **admin API + Admin settings page** to create, list, rotate, and revoke service accounts, gated behind new `service_account.*` authorization actions held by `admin`/`super_admin`; every lifecycle mutation and every token issuance is audited (never recording the secret or the token).
- Out of scope (deferred, deliberately, but the token model is shaped to accept them additively): OIDC workload-identity federation for CI/release agents, token attenuation for sub-agent delegation (Biscuit/macaroon-shaped), DPoP/mTLS sender-constraining of service-account tokens, and asymmetric (RS256/ES256) signing. Per-action custom scopes beyond role binding are also deferred; a service account binds to a seeded role this wave.

## Capabilities

### New Capabilities

- `server-identity-service-accounts`: the service-account principal and its lifecycle (create/list/rotate/revoke), the hashed-at-rest client credential, the client-credentials token endpoint, the short-lived self-validating access token and its stateless verification, revocation via the per-replica epoch snapshot, the `service_account.*` authorization actions, the audit trail on lifecycle and issuance, and the Service-accounts admin settings page.

### Modified Capabilities

- `server-identity-authentication`: add the bearer transport for the API. A request presenting a valid service-account access token authenticates as the bound service-account principal; the cookie + CSRF transport remains the browser path. Both transports resolve to the same actor abstraction through one verification path; the API bearer boundary does not require CSRF.
- `server-identity-authorization`: a service-account principal resolves to an `Actor` carrying the service account's role and is evaluated by the same chokepoint as a human actor; add `service_account.read`, `service_account.create`, `service_account.rotate`, and `service_account.revoke` to the registered action enumeration, granted to `admin` and `super_admin`. Destructive actions remain reauth-gated for human sessions; a service-account actor is never "fresh" and therefore cannot perform reauth-gated actions unless its role explicitly grants them through a non-reauth path (see design).

## Impact

- Code: `server/identity` (new service-account store + migration, token-issuance service, bearer middleware on the API mux, epoch-snapshot revocation reusing the #454 pattern), `server/identity/api/authz.go` (new actions + service-account actor resolution), `internal/keyring` (new `edr/service-account-token/sign/v1` label), the audit pipeline (lifecycle + issuance events), and the React UI (`ui/src/` new Service-accounts settings page).
- Data: new MySQL table(s) for service accounts and their hashed credentials (with an epoch column for revocation). Forward-only schema migration.
- APIs: new `POST /api/token` (client-credentials grant, unauthenticated-by-cookie, authenticated by credential), and `GET`/`POST`/`DELETE` `/api/settings/service-accounts` management routes under the operator-session + CSRF boundary. The existing API routes gain a second accepted authenticator (the bearer access token) alongside the session cookie.
- No change to the agent protocol, the events schema, or the persisted host token; the host-token mechanism is generalized, not altered. Rollback is a code revert plus dropping the new tables; deployments using only cookie sessions are unaffected.
