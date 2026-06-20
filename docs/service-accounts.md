# Service accounts (API access)

Service accounts are non-human principals for automation, CI/release pipelines, and AI agents that call the EDR API directly. They authenticate with the OAuth 2.1 client-credentials grant: a long-lived credential is exchanged for a short-lived bearer access token (ADR-0013). The credential is never sent on ordinary API calls, and the access token is validated statelessly, so the API hot path scales with the number of agents.

## Model

- A service account is an identity of kind `api_token` bound to exactly one operational role (`analyst`, `senior_analyst`, or `auditor`). It can never be bound to `admin`/`super_admin` or any role granting the console-management actions (`service_account.*`, `user.*`, `sso.manage`): a service account cannot create, rotate, or revoke other service accounts, invite users, or change SSO. Pick the least-privileged role that covers the automation's needs.
- The credential is a `client_id` (prefix `sa_`) plus a `client_secret` (prefix `edrsa_`). The secret is shown exactly once, at creation or rotation, and is stored only as a SHA-256 hash. If it is lost, rotate; it cannot be recovered.
- The credential carries an expiry (90 days by default, 365 days maximum).

## Managing service accounts

Service accounts are managed from the Admin settings area (requires the `service_account.*` permissions, held by `admin`/`super_admin`) or via the admin API:

- `GET /api/settings/service-accounts` lists accounts (name, role, status, last used). Never returns secrets.
- `POST /api/settings/service-accounts` creates one. Body: `{"name": "...", "role": "analyst", "expires_in_days": 90}` (`expires_in_days` optional). The response includes the `client_id` and the one-time `secret`.
- `POST /api/settings/service-accounts/{id}/rotate` issues a new secret and bumps the account's revocation epoch, so access tokens minted from the old secret stop working. Use this after a suspected leak.
- `DELETE /api/settings/service-accounts/{id}` revokes the account: it can no longer mint tokens, and outstanding access tokens stop validating within the revocation refresh window (about 5 seconds).

Every lifecycle change and every token issuance is audited; no audit row, log line, or API response ever contains the secret or an access token.

## Obtaining and using an access token

Exchange the credential at the token endpoint for a 15-minute access token, then present it as a bearer token. The token endpoint accepts form-encoded (the OAuth standard) or JSON bodies.

```bash
# 1. Get an access token (client-credentials grant).
ACCESS_TOKEN=$(curl -s https://edr.example.com/api/oauth/token \
  -d grant_type=client_credentials \
  -d client_id="$EDR_CLIENT_ID" \
  -d client_secret="$EDR_CLIENT_SECRET" | jq -r .access_token)

# 2. Call the API with the bearer token (no CSRF token needed on the bearer path).
curl -s https://edr.example.com/api/hosts \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

The token response is `{"access_token": "...", "token_type": "Bearer", "expires_in": 900}`. There is no refresh token: cache the access token and re-run the grant shortly before it expires (or on a `401`). The token's authority is exactly the bound role's permissions, evaluated by the same authorization chokepoint as a human operator.

## Notes and limits

- The token endpoint is rate-limited per `client_id`. A well-behaved client mints roughly once per token lifetime; bursts beyond the limit receive `429`.
- Access tokens are signed with a key derived from `EDR_SECRET_KEY`. Rotating that root secret (or losing it) invalidates all outstanding access tokens; service accounts then obtain fresh tokens at the next grant. The stored credential hashes are unaffected.
- Deferred (tracked for later): OIDC workload-identity federation for keyless CI access, token attenuation for sub-agent delegation, and DPoP/mTLS sender-constraining. See ADR-0013.
