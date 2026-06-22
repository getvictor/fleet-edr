## Context

The server authenticates humans today only through a server-side session row keyed by `SHA-256(cookie token)` (`server/identity/internal/middleware/session.go`), with CSRF on state-changing methods. Agents authenticate through a separate, newer path: `server/endpoint/internal/signedtoken` issues `v1.<claims>.<HMAC-SHA256>` tokens keyed off `EDR_SECRET_KEY` (keyring label `edr/host-token/sign/v1`), self-validated locally with no DB read, revoked via a per-replica epoch snapshot refreshed every few seconds, and refreshed by the agent at `POST /api/token/refresh` (#454). There is no credential for a non-human API caller.

This change adds that credential. It is the Service-accounts half of the wave-2 user-management arc (alongside #135 role management and the already-shipped #375 SSO config). The deployment is multi-replica and stateless (ADR-0010, ADR-0011): durable cross-request state lives in MySQL, no shared in-process state may be required to serve the next request, so the API request path must not do a credential read per call. The identity context is a bounded context (ADR-0004); the token-issuance and verification surface is owned by `server/identity` and exposed only through `server/identity/api`. ADR-0013 records the credential-model decision this change implements.

## Goals / Non-Goals

**Goals:**

- A non-human principal calls the EDR API with `Authorization: Bearer <token>`, resolving to the same `Actor` + permission set, through the same authz chokepoint, as a human operator.
- The API request hot path stays stateless: the access token is validated locally (signature + `exp` + `aud`) with no per-request DB read, so it scales with the agent population.
- The long-lived credential is hashed at rest, shown once, scoped to a single role, and revocable; a revoked service account stops working within the epoch-snapshot refresh window.
- Service-account lifecycle and token issuance funnel through the authz chokepoint and are audited, never recording the secret or the token.
- Reuse the #454 signer, the keyring, the sessions hashing, and the one chokepoint; introduce no second auth stack.

**Non-Goals:**

- OIDC workload-identity federation (CI/release agent exchanges its platform OIDC identity for an EDR token, no static secret). Design-compatible; deferred.
- Token attenuation for sub-agent delegation (Biscuit/macaroon-shaped) and DPoP/mTLS sender-constraining of service-account tokens. Deferred; the endpoint agent is already mTLS sender-constrained via its Secure Enclave identity.
- Asymmetric (RS256/ES256, RFC 9068) signing. Deferred; recorded as the migration target if verification is ever externalized.
- Per-action custom scopes beyond role binding, and multiple roles per service account. A service account binds to one seeded role this wave.
- Refresh tokens. Machine clients re-run the client-credentials grant near expiry.

## Decisions

### Decision: OAuth 2.1 client-credentials, two tiers (long-lived credential -> short-lived token)

A service account presents its credential to `POST /api/token` and receives a short-lived access token; the credential never travels on subsequent API calls. Tier 1 (the credential) is long-lived, hashed at rest, and revocable; tier 2 (the access token) is short-lived and validated statelessly. This is the pattern every surveyed platform converges on (GitHub App key -> 1 h installation token; AWS role -> STS session; Kubernetes -> bound token; GCP -> short-lived token), and it keeps revocability (delete/disable the credential) without putting a per-request read on the hot path.

*Alternatives considered:* DB-hashed opaque token validated per request (rejected: a MySQL read per API call does not scale with agents and pushes shared state onto the hot path, against ADR-0010; we keep DB-hashing for the credential, not the request path); opaque token + RFC 7662 introspection (rejected: the introspection endpoint is a hot dependency / SPOF with the same per-request cost plus more parts); long-lived static API key (rejected: anti-pattern for agents, no scoping, hard revocation/audit).

### Decision: Generalize the #454 signed-token machinery; symmetric HMAC under a new keyring label

The access token reuses `signedtoken`'s `v1.<claims>.<HMAC-SHA256>` format, signed with a key derived from `EDR_SECRET_KEY` under a new label `edr/service-account-token/sign/v1`. Claims: `sub` (service-account id), `aud` (this deployment's identifier), role/scope, `iat`, `exp`, `kid`, `jti`. Verification is local (signature + `exp` + `aud`), no DB read. Symmetric HMAC is correct here because the server is both the authorization server and the resource server in one trust domain; every replica derives the same key. A leaked `EDR_SECRET_KEY` already forges host tokens and session cookies, so this concentrates rather than expands the existing root-of-trust blast radius.

*Alternatives considered:* asymmetric RS256/ES256 per RFC 9068 (deferred: only needed when a separate party verifies without the signing secret; switching later does not change the model); a distinct token format (rejected: a second self-validating format with no benefit; reuse keeps one verifier to audit).

### Decision: Revocation via short TTL plus a per-replica epoch snapshot, not per-request lookup

Each service account carries an epoch. Disabling or revoking it bumps the epoch. Each replica refreshes a snapshot of `{service_account_id -> epoch, revoked_at}` from MySQL on a short fixed interval (≈5 seconds, matching the #454 host-token snapshot cadence) and rejects a presented token whose epoch is stale. Combined with the 15-minute TTL, this bounds the worst-case validity of a revoked token to the refresh window without a per-request read, and no new token can be minted because the credential is gone. The snapshot is a per-replica cache that is safe to lose and rebuilds from MySQL (explicitly allowed under ADR-0010).

*Alternatives considered:* a `jti` denylist checked per request from a shared store (rejected for v1: adds a hot dependency for a property the epoch snapshot already delivers; revisit if instant, per-token revocation is ever required); rely on TTL alone with no epoch (rejected: a 15-minute window with no kill switch is too weak for a security product's "revoke this integration now" expectation).

### Decision: 15-minute access-token TTL, no refresh token

Machine-client norms cluster at 5-15 minutes (with GitHub App tokens at 1 h). We choose 15 minutes: long enough that the grant round-trip is negligible overhead, short enough that the epoch snapshot is a backstop rather than the primary control. Clients cache the token until ~80% of TTL and re-run the grant on expiry or `401`. No refresh token is issued: the long-lived credential is the refresh capability, which avoids refresh-token rotation/replay machinery for a caller that already holds a durable secret.

### Decision: Service account is an `identities` row of kind `api_token`, bound to one role

A service account reuses the identity model: a row in `identities` with provider kind `api_token` (the reserved kind), no associated human user, bound to exactly one seeded role. The bound role MAY be any seeded role except `super_admin`, which is rejected (the unrestricted wildcard is never warranted for a non-human credential). `admin` is permitted at operator discretion: an admin-bound service account holds the console-management actions (`service_account.*`, `user.*`, `sso.manage`) and is a full-control credential that can mint more service accounts, so the UI and docs steer operators toward the least-privileged role, but automation that genuinely needs admin is allowed it. The bearer middleware resolves a verified token to an `Actor` carrying that role, with the actor's auth-method marked as bearer so the reauth freshness gate (which applies only to session-authenticated human actors) skips it. A service-account actor is never `SessionFresh`, so it cannot perform reauth-gated destructive actions (`host.isolate`, `host.kill_process`, `host.run_script`) through the human reauth path; if automation must perform a response action, the role grants it and the chokepoint evaluates it without the freshness gate, which applies only to interactive sessions. This keeps the destructive-action posture explicit rather than accidentally opening it to every token.

*Alternatives considered:* a standalone service-account table divorced from `identities` (rejected: duplicates principal/role wiring and the chokepoint's actor resolution; the identity model already has the `api_token` kind reserved); multiple roles or arbitrary action sets per service account (deferred: role binding is sufficient this wave and keeps least-privilege legible).

### Decision: Credential format is a prefixed, checksummed secret hashed at rest

The secret is emitted once as `<prefix>_<random>` with a trailing checksum (GitHub-style), enabling offline rejection of malformed tokens and secret-scanning, and is stored only as `SHA-256(secret)`. The token endpoint looks up the credential by `client_id`, then compares `SHA-256(presented secret)` against the stored hash in constant time (the existing constant-time analogue is the CSRF-token comparison in `session.go`; the session-cookie lookup itself keys on the digest rather than comparing). The read/list API returns metadata and `secret_set`/last-used, never the secret.

### Decision: HTTP surface

`POST /api/token` (client-credentials grant: accepts the credential, returns `{access_token, token_type: "Bearer", expires_in}`; authenticated by the credential, not a cookie; CSRF-exempt). Management routes under the operator-session + CSRF boundary, gated on the new `service_account.*` actions: `GET /api/settings/service-accounts` (list, no secrets), `POST /api/settings/service-accounts` (create, returns the secret once), `POST /api/settings/service-accounts/{id}/rotate` (rotate, returns the new secret once), `DELETE /api/settings/service-accounts/{id}` (revoke). Every existing API route gains the bearer access token as a second accepted authenticator alongside the session cookie, resolved by a shared actor-resolution step.

## Risks / Trade-offs

- **Two token formats coexist** (server-side session rows for humans; signed self-validating tokens for machines/hosts). Mitigation: both resolve through one authz chokepoint; a reviewer rejects any third format. ADR-0013 records this cost.
- **Revocation is eventually consistent** within the epoch-snapshot refresh window, not instant. Matches host tokens; documented. Deployments needing stricter revocation shorten the access-token TTL.
- **Token issuance is new attack surface.** Mitigations: constant-time credential comparison, rate-limiting the token endpoint, hashed-at-rest secrets shown once, audit on issuance, and the access token's audience binding so a token minted for this deployment is useless elsewhere.
- **`EDR_SECRET_KEY` is a single root of trust** for sessions, host tokens, and now service-account tokens. Already true; this change does not widen it but raises the stakes of its rotation story (tracked with the keyring's `kid` versioning).

## Open Questions

- Should `POST /api/token` live under `/api/token` (shared with the host-token refresh route family) or a distinct `/api/oauth/token` path? Leaning `/api/token` for symmetry with #454, but the host route is host-token-middleware-gated, so the grant needs its own un-cookie'd sub-path.
- Default and maximum credential lifetime: propose 90-day default, deployment-configurable maximum. Confirm against pilot expectations.
- Whether to expose token-issuance metrics (issued/refused per service account) in the UI this wave or defer to the observability arc.
