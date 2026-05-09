# Okta SSO setup

The EDR server speaks OIDC with PKCE. Okta is the reference IdP for
v1 deployments - every other conformant OIDC provider follows the
same shape, but the screen names and field labels in this guide are
Okta's. Sister IdPs (Azure AD, Google Workspace, Auth0) need only the
issuer URL, client ID, client secret, and redirect URL adjusted; the
EDR-side env vars do not change.

This is a wave-1 setup: SSO covers everyday operator login. The
break-glass account at `admin@fleet-edr.local` is the only path in
when SSO is unavailable (see `docs/breakglass.md`).

## Prerequisites

- An Okta tenant with admin access. Free developer tenants
  (`*.okta.com`, `*.oktapreview.com`) work for staging; production
  deployments use the customer's existing tenant.
- The externally reachable HTTPS URL of the EDR server. The redirect
  URL must use `https://` for production tenants - Okta rejects
  `http://` redirect URLs outside `localhost`.
- The break-glass account already redeemed (so an operator can
  recover if SSO breaks during config). See `docs/breakglass.md`.

## Create the application

1. In the Okta admin console, go to **Applications -> Applications**
   and click **Create App Integration**.
2. Pick **OIDC - OpenID Connect** as the sign-in method, and
   **Web Application** as the application type. Click Next.

The choice matters: the EDR server holds a client secret and
exchanges the authorization code server-side, which is the Web
Application shape. Do not pick SPA (no client secret) or Native
(no client secret + no redirect to a server).

## Configure the redirect

In the **General Settings** step:

| Field | Value |
|---|---|
| App integration name | `Fleet EDR` (or any operator-friendly name) |
| Logo | optional |
| Grant type | Authorization Code (default; do not enable Implicit) |
| Sign-in redirect URIs | `https://<edr-host>/api/auth/callback` |
| Sign-out redirect URIs | `https://<edr-host>/ui/login` |
| Trusted Origins | leave empty unless you also want CORS for the same host |

Replace `<edr-host>` with the externally reachable host that browsers
hit. The EDR server validates that the `redirect_uri` it sends to
Okta exactly matches `EDR_OIDC_REDIRECT_URL`, which itself must
exactly match the value Okta has on file: query strings, trailing
slashes, and case all matter.

The sign-out redirect is informational for the wave-1 build (the EDR
UI's logout calls `POST /api/auth/logout` to drop the local session,
not Okta's RP-initiated logout). It still needs to be on Okta's
allowlist if you ever add the RP-initiated path; preconfiguring it
costs nothing.

## Assignments

In the **Assignments** step:

- Pick **Allow everyone in your organization to access** for a small
  pilot, OR **Limit access to selected groups** and bind a group
  (typically `edr-operators`) for tighter control.
- Click **Save**.

Wave-1 does NOT consume Okta groups. Every JIT-provisioned user
lands in the `super_admin` role for now (see
`openspec/specs/identity-roles/spec.md`). Wave-2 will add a
`groups` claim to the scope set and map Okta groups to EDR roles;
until then, who can sign in is the only knob.

## Note the client credentials

After creation, Okta lands on the application's **General** tab.
Record three values; the EDR server reads each one as an env var:

| Okta field | EDR env var |
|---|---|
| Client ID | `EDR_OIDC_CLIENT_ID` |
| Client Secret | `EDR_OIDC_CLIENT_SECRET` |
| Okta domain (in the **Sign On** tab as the issuer URL, e.g. `https://your-tenant.okta.com`) | `EDR_OIDC_ISSUER` |

The client secret is shown once on creation. Store it in the same
secret manager that holds `EDR_SESSION_SIGNING_KEY` (Vault, AWS
Secrets Manager, docker-compose `secrets:` mount, etc.); the EDR
server reads each `EDR_*` value from a `*_FILE` sibling if the bare
env var is empty, so a file-backed mount works without exposing the
plaintext in the compose env block.

If the client secret leaks, **rotate immediately**: Okta admin
console -> Applications -> the EDR app -> **General** -> **Client
Credentials** -> **Generate new secret**. Update
`EDR_OIDC_CLIENT_SECRET` (or the secret file) on the EDR server and
restart. Existing sessions stay valid (sessions are signed with
`EDR_SESSION_SIGNING_KEY`, not the client secret); only fresh
sign-ins use the new secret.

## Configure the EDR server

Set these env vars on the server process (systemd unit, k8s
Deployment, docker-compose, whichever shape the deployment uses):

```bash
EDR_OIDC_ISSUER=https://your-tenant.okta.com
EDR_OIDC_CLIENT_ID=0oaXXXXXXXXXXXXXXXXX
EDR_OIDC_CLIENT_SECRET=<the secret from above>
EDR_OIDC_REDIRECT_URL=https://<edr-host>/api/auth/callback
EDR_SESSION_SIGNING_KEY=<random 32+ bytes, base64 or raw>
```

Optional knobs (defaults shown):

```bash
EDR_OIDC_SCOPES=openid,email,profile
EDR_OIDC_ALLOW_JIT_PROVISIONING=1
EDR_OIDC_STATE_COOKIE_TTL=5m
EDR_SESSION_IDLE_TIMEOUT=8h
EDR_SESSION_ABSOLUTE_TIMEOUT=24h
EDR_REAUTH_WINDOW=30m
```

Notes on the optional knobs:

- **Scopes.** The wave-1 default `openid,email,profile` gives the
  callback the claims the JIT provisioner needs (`sub`, `email`,
  `name`). Adding scopes Okta hasn't granted on the application
  fails the consent step at Okta, not the EDR server. Do not add
  `groups` until wave-2.
- **JIT provisioning.** `EDR_OIDC_ALLOW_JIT_PROVISIONING=1`
  (default) creates a user + identity + default role binding on
  first successful sign-in. Set to `0` to require an operator to
  pre-create the user via SQL; an unknown subject then sees a
  directed `403 unknown_subject` instead of being auto-onboarded.
- **State cookie TTL.** Defaults to 5 minutes - long enough for a
  password manager and an MFA prompt. Tune up for tenants that gate
  on slow upstream MFA (push notifications, hardware key roundtrip).
- **Session timeouts.** OIDC-minted sessions slide on every
  authenticated request up to `EDR_SESSION_ABSOLUTE_TIMEOUT`. The
  reauth window applies to destructive actions (`host.isolate`,
  `host.kill_process`, `host.run_script`,
  `alert.resolve` when severity=critical) and forces a fresh IdP
  prompt when `last_auth_at` is older than `EDR_REAUTH_WINDOW`.

The server refuses to start if `EDR_OIDC_ISSUER` is set without the
matching client ID / secret / redirect URL - boot-time validation
prints a single error block listing every missing knob.

## Verify

1. Open `https://<edr-host>/ui/login` in a browser that is NOT
   already signed into Okta.
2. Click **Continue with single sign-on**. The browser bounces to
   Okta, prompts for the user, and (if MFA is enforced on the
   tenant) prompts for the second factor.
3. On success, Okta redirects to `/api/auth/callback?...` and the
   EDR server redirects you to `/ui/`. The top nav shows the
   signed-in user's email.
4. Open a new browser profile (or incognito) and try a user that is
   **not** assigned to the application. Okta serves its own access
   denied page; you never reach the EDR server.

The server emits `auth.oidc.success`, `auth.oidc.failure`, or
`auth.oidc.callback.error` audit rows on every flow:

```sql
SELECT id, occurred_at, action, actor_email, payload
FROM audit_events
WHERE action LIKE 'auth.oidc.%'
ORDER BY occurred_at DESC
LIMIT 50;
```

The `payload.reason` column on a failure narrows the cause
(`unknown_subject`, `email_conflict`, `state_mismatch`,
`exchange_failed`, etc.). Cross-reference with
`docs/threat-model.md` for the threats each failure mode covers.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Browser hits Okta then bounces back to `/ui/login?error=invalid_state` | Cookie blocked by browser, or load balancer stripped the `Secure` cookie over plaintext HTTP | Confirm the EDR server is reached over HTTPS end-to-end; the state cookie is `Secure` and the browser drops it on plaintext |
| `error=state_mismatch` | The state cookie was minted by a different EDR instance than the one handling the callback | Pin the load balancer's session affinity, or scale to a single instance for the callback path. The state cookie is HMAC-signed, but each instance reads it from the per-flow cookie value, not a shared store |
| `error=unknown_subject` with JIT enabled | Okta issued a `sub` for a user that the EDR is treating as new - usually a duplicate-user race; check `users` for an earlier row with the same `email` | Either delete the orphan row or set `EDR_OIDC_ALLOW_JIT_PROVISIONING=0` and pre-provision via SQL |
| `error=email_conflict` | An existing `users` row has the email but is bound to a different OIDC subject (typical of re-tenanted Okta orgs) | Have an admin merge the rows in SQL: update `identities.subject` on the canonical user, delete the duplicate row |
| `error=exchange_failed` | Okta token endpoint unreachable, or client secret rotated without restarting the EDR server | Curl `https://<okta-host>/oauth2/v1/token` from the EDR host; restart the EDR server after a secret rotation |
| Browser sits on Okta and never redirects | Sign-in redirect URI on the Okta app does not exactly match `EDR_OIDC_REDIRECT_URL` | Compare both for trailing slashes, query strings, scheme, and casing |

## Related docs

- `docs/breakglass.md` - the recovery path when SSO is unavailable.
- `docs/install-server.md` - the rest of the `EDR_*` env vars the
  server reads at boot.
- `docs/authz.md` - the role bindings JIT-provisioned OIDC users
  inherit (wave-1: every new identity lands in `super_admin`).
- `docs/threat-model.md` - the threat coverage the OIDC + reauth
  controls close.
