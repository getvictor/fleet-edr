# 0013. Service-account and API authentication: client-credentials with short-lived self-validating tokens

- Status: Accepted
- Date: 2026-06-20
- Deciders: getvictor

## Context

The product needs non-human principals: automation, CI/release pipelines, and increasingly AI agents that call the EDR API directly rather than through the browser. Issue #376 ("Support API-only users") is the first concrete consumer, and the SSO config work (#375) flagged that we owe an ADR pinning down the credential model before we build on top of it.

The constraint we set during the #375 design discussion was "one credential model, two transports": a human session rides in a cookie (with CSRF) for the browser, and the same authorization model is reached over `Authorization: Bearer` for the API. We explicitly did not want a second, parallel auth stack (the personal-access-token sprawl that GitHub/Stripe accumulated). Whatever a service account presents must resolve to the same `Actor` + permission set, through the same authorization chokepoint (`server/identity/api/authz.go`), as a human operator.

Two existing primitives bound the design:

- **The server is stateless and multi-replica behind a load balancer (ADR-0010, ADR-0011).** Any replica serves any request; no shared in-process state may be required to serve the next one. A credential-validation path that does a MySQL read on every API request is a scaling liability precisely as the agent population grows, which is the case we are designing for.
- **#454 already shipped the right shape for hosts.** `server/endpoint/internal/signedtoken` issues `v1.<claims>.<HMAC-SHA256>` tokens, keyed off `EDR_SECRET_KEY` via the keyring label `edr/host-token/sign/v1`, self-validated locally with no DB read, with revocation handled by a per-replica epoch snapshot refreshed every few seconds and an agent-pull refresh at `POST /api/token/refresh`. This is a single-trust-domain adaptation of the OAuth client-credentials pattern.

Research into current practice (IETF OAuth 2.1, RFC 9068 JWT access tokens, RFC 7662 introspection, RFC 9449 DPoP, RFC 8705 mTLS-bound tokens) and into how GitHub, Stripe, AWS/STS, Google Cloud, and Kubernetes authenticate machines at scale produced one consistent pattern: a long-lived, revocable credential is exchanged for a short-lived (≈15 min to 1 h) token that is validated statelessly on the hot path; the durable secret never travels on every request; static long-lived API keys are treated as an anti-pattern for proliferating agents. The AI-agent frontier (MCP authorization spec, workload identity federation, token attenuation) adds audience-binding, least-privilege scoping, and federation as the forward-looking properties to design toward, not necessarily to build now.

## Decision

Service accounts authenticate with the **OAuth 2.1 client-credentials grant**, exchanging a long-lived, hashed-at-rest credential for a **short-lived, self-validating signed access token** that is validated statelessly on the API request path. We generalize the #454 host-token machinery rather than introduce a second mechanism. Concretely:

- **Two transports, one authorization model.** Browser: session cookie + CSRF. API / service account: `Authorization: Bearer <access-token>`, CSRF-exempt (a bearer token is not an ambient credential). Both resolve to the same `Actor` + permission set through the existing authz chokepoint. Handlers stay auth-agnostic.
- **Tier 1, the credential (long-lived, revocable, low-frequency).** A service account is an `identities` row with provider kind `api_token` (the reserved kind), bound to a principal and a role. Its credential (`client_id` + secret, secret carrying a self-describing prefix + checksum) is stored **hashed** (SHA-256, as sessions already are), shown once, never re-displayed, and is touched only at the token endpoint. It carries a mandatory, configurable maximum lifetime.
- **Tier 2, the access token (short-lived, stateless, high-frequency).** `POST /api/token` performs the client-credentials grant and returns a signed access token reusing `signedtoken` under a new keyring label `edr/service-account-token/sign/v1`. Claims: subject (service-account id), `aud` (this deployment), role/scope, `iat`, `exp` (15 minutes), `kid`, `jti`. It is verified locally on every request (signature + `exp` + `aud`) with **no DB read**, exactly as host tokens are.
- **Revocation = short TTL + per-replica epoch snapshot.** Disabling or revoking a service account bumps its epoch; each replica refreshes the epoch snapshot from MySQL every few seconds (the host-token mechanism, generalized), so outstanding tokens stop validating within the refresh window without a per-request lookup, and no new token can be minted because the credential is gone. There is no refresh token: a client re-runs the grant near expiry, the credential being its refresh capability.
- **Symmetric signing (HMAC-SHA256), deliberately.** The server is both the authorization server and the resource server in one trust domain; every replica derives the same key from `EDR_SECRET_KEY`. Asymmetric RS256/ES256 (RFC 9068) is the standard only when a separate party must verify without the signing secret, which we do not have. Switching to asymmetric later, if verification is ever externalized, does not change this model.
- **Least privilege + audit.** A service account is bound to a single seeded role; `super_admin` is never bindable to a non-human credential. (Amended 2026-06-21: `admin` is permitted at operator discretion. An admin-bound service account holds the console-management actions including `service_account.*`, so its token is a full-control credential that can mint more service accounts; operators are guided toward the least-privileged role that satisfies the automation. The original posture excluded `admin` too; product chose to allow it for automation that legitimately needs admin.) The token is audience-bound. Service-account lifecycle and token issuance are audited; "use" (every authorized API call) is not, because chokepoint read-allow events are sampled, so this records the lifecycle + issuance events plus the existing privileged-mutation audits. Managing service accounts is gated behind new `service_account.*` actions held by `admin`/`super_admin`.
- **Scope boundary.** This decision governs operator-facing API and service-account credentials. The agent enrollment and host-token channel (#454) is a separate trust boundary with its own credential lifecycle and is out of scope here. The browser session cookie retains its `HttpOnly` / `Secure` / `SameSite` posture and CSRF protection (CSRF is a cookie-transport property; a bearer token, not being an ambient credential, is immune by construction and so the API bearer path is CSRF-exempt).

## Consequences

- **Easier**: the API hot path stays stateless and scales horizontally with the agent population (no per-request credential read); the model reuses #454's signer, the keyring, the sessions hashing, and the one authz chokepoint, so there is no second auth stack to maintain; a leaked access token self-expires in 15 minutes.
- **Harder / the cost**:
  - There are now two token _formats_ in the system (server-side session rows for humans, signed self-validating tokens for machines and hosts). The mitigation is that both resolve through one authorization path; a reviewer should reject any third format.
  - Revocation is **eventually consistent** within the epoch-snapshot refresh window, not instant. This matches host tokens and is documented; deployments that need stricter revocation can shorten the access-token TTL.
  - A leaked `EDR_SECRET_KEY` lets an attacker forge service-account tokens, but it already lets them forge host tokens and session cookies; this concentrates rather than expands the existing root-of-trust blast radius.
  - We take on a token-issuance endpoint and a credential lifecycle (create / list / rotate / revoke) as new surface, with the attendant secret-handling care.
- **Accepted gaps (deferred, design-compatible)**: OIDC workload-identity federation (a CI/release agent exchanges its GitHub Actions OIDC identity for an EDR token, holding no static secret), token attenuation for sub-agent delegation (Biscuit/macaroon-shaped), and DPoP/mTLS sender-constraining are not built now. The token model is shaped so each is additive. The macOS endpoint agent is already transport-sender-constrained via its Secure Enclave mTLS identity, so endpoint tokens do not need DPoP.

## Alternatives considered

**DB-hashed opaque token validated per request.** The simplest model and the first one proposed in discussion: present an opaque bearer key, hash it, look it up. Attractive for instant revocation (delete the row). Rejected as the hot-path mechanism: a MySQL read on every API call does not scale as the agent population grows, and it pushes shared state onto the critical path against the spirit of ADR-0010. The two-tier model keeps the same revocability (the credential is the revocable thing) while leaving the hot path stateless. We keep DB-hashing for the long-lived credential, where it belongs.

**Opaque token + introspection (RFC 7662).** Validate by calling an introspection endpoint. Rejected: the introspection endpoint becomes a hot internal dependency and SPOF with the same per-request-lookup cost as the DB approach, plus more moving parts. In a monolith, self-validation is strictly better.

**Asymmetric JWT access tokens (RS256/ES256, RFC 9068).** The cross-vendor standard. Considered and deliberately not adopted now because we have a single trust domain; HMAC reusing the existing signer is simpler and consistent with #454. Recorded as the migration target if token verification is ever externalized to a separate service.

**Long-lived static API keys (no token exchange).** What a naive "API users" feature would ship. Rejected: long-lived, rarely scoped, easily leaked, hard to revoke and audit at agent scale; an industry-recognized anti-pattern for non-human identities.

**Embed a full OAuth authorization server (Keycloak / Ory Hydra).** Standards-complete out of the box. Rejected: a heavy operational dependency for a self-hosted single-binary product when we already hold the signing, identity, and authorization primitives needed to issue client-credentials tokens ourselves.

## References

- Issue #376 (API-only users / `api_token` identity kind) and #135 (role-management UI), the wave-2 user-management arc this underpins
- #454 (`server/endpoint/internal/signedtoken`, `server/endpoint/internal/token`): the self-validating signed host token + agent-pull refresh this generalizes
- ADR-0010 ([`0010-stateless-server.md`](0010-stateless-server.md)) and ADR-0011 ([`0011-ha-architecture.md`](0011-ha-architecture.md)): the stateless multi-replica topology the stateless hot path serves
- ADR-0004 ([`0004-modular-monolith-bounded-contexts.md`](0004-modular-monolith-bounded-contexts.md)): the identity bounded context that owns the new surface
- `openspec/changes/service-account-auth/`: the change proposal implementing this decision
- RFC 6749 / OAuth 2.1 (client-credentials grant), RFC 9068 (JWT access tokens), RFC 7662 (token introspection), RFC 9449 (DPoP), RFC 8705 (mTLS-bound tokens), RFC 8707 (resource indicators / audience)
- Prior art surveyed: GitHub App installation tokens (1 h, key-signed exchange), AWS STS AssumeRole, Google Cloud short-lived tokens + Workload Identity Federation, Kubernetes bound ServiceAccount tokens (TokenRequest), the MCP authorization spec (OAuth 2.1 resource server + audience binding)
