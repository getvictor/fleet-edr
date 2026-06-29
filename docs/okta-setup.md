# Okta SSO setup

The EDR server speaks OIDC with PKCE. Okta is the reference IdP: every other conformant OIDC provider follows the same shape, but the screen names and field labels in this guide are Okta's. Sister IdPs (Azure AD, Google Workspace, Auth0) need only the issuer URL, client ID, client secret, and external URL adjusted; the EDR-side flow does not change.

SSO covers everyday operator login. The break-glass account at `admin@fleet-edr.local` is the only path in when SSO is unavailable (see [`breakglass.md`](breakglass.md)).

SSO is configured entirely in the UI under **Admin settings -> Single sign-on**; the stored configuration is the source of truth and survives restarts. The server reads no `EDR_OIDC_*` environment variables.

## Configure SSO in the UI

OIDC is configurable in-product under **Admin settings -> Single sign-on** (the account menu, top right; visible to operators with the `sso.manage` permission). An admin sets the issuer, client ID, client secret (write-only: enter a value to rotate, never displayed), the deployment external URL, and the default JIT role, then saves. The settings page does not expose a JIT on/off toggle: just-in-time provisioning is always on, so anyone who signs in through the provider is auto-created with the default role (the operator-invite flow that would let an admin pre-provision users and turn JIT off is not built yet). Changes apply at runtime with no restart, and the test-connection button verifies the provider before saving.

The server always boots without any OIDC configuration, so on a fresh deployment you sign in with the break-glass admin first (see [`breakglass.md`](breakglass.md)), then fill in this form. The redirect URI is derived from the external URL (`<external-url>/api/auth/callback`) and shown read-only; register that exact value at the IdP.

The stored client secret is sealed with a key derived from `EDR_SECRET_KEY`. Rotating `EDR_SECRET_KEY` makes the stored secret undecryptable; after such a rotation, re-enter the client secret in the UI.

## Prerequisites

- An Okta tenant with admin access. Free developer tenants (`*.okta.com`, `*.oktapreview.com`) work for staging; production deployments use the customer's existing tenant.
- The externally reachable HTTPS URL of the EDR server. The redirect URL must use `https://` for production tenants. Okta rejects `http://` redirect URLs outside `localhost`.
- The break-glass account already redeemed (so an operator can recover if SSO breaks during config). See [`breakglass.md`](breakglass.md).

## Create the application

1. In the Okta admin console, go to **Applications -> Applications** and click **Create App Integration**.
2. Pick **OIDC (OpenID Connect)** as the sign-in method, and **Web Application** as the application type. Click Next.

The choice matters: the EDR server holds a client secret and exchanges the authorization code server-side, which is the Web Application shape. Do not pick SPA (no client secret) or Native (no client secret + no redirect to a server).

## Configure the redirect

In the **General Settings** step:

| Field                  | Value                                                   |
| ---------------------- | ------------------------------------------------------- |
| App integration name   | `Fleet EDR` (or any operator-friendly name)             |
| Logo                   | optional                                                |
| Grant type             | Authorization Code (default; do not enable Implicit)    |
| Sign-in redirect URIs  | `https://<edr-host>/api/auth/callback`                  |
| Sign-out redirect URIs | `https://<edr-host>/ui/login`                           |
| Trusted Origins        | leave empty unless you also want CORS for the same host |

Replace `<edr-host>` with the externally reachable host that browsers hit. The EDR server derives the `redirect_uri` it sends to Okta from the stored external URL (`<external-url>/api/auth/callback`); that derived value must exactly match the value Okta has on file: query strings, trailing slashes, and case all matter.

The sign-out redirect is informational in the current release (the EDR UI's logout calls `DELETE /api/session` to drop the local session, not Okta's RP-initiated logout). It still needs to be on Okta's allowlist if you ever add the RP-initiated path; preconfiguring it costs nothing.

## Assignments

In the **Assignments** step:

- Pick **Allow everyone in your organization to access** for a small pilot, OR **Limit access to selected groups** and bind a group (typically `edr-operators`) for tighter control.
- Click **Save**.

The current release does NOT consume Okta groups. Every JIT-provisioned user lands in the lowest-privilege role (`analyst`); see [`authz.md`](authz.md) for the role matrix. An `admin` promotes the new operator from the Users page in **Admin settings -> Users**. A future release will add a `groups` claim to the scope set and map Okta groups to EDR roles; until then, who can sign in is the only knob.

## Note the client credentials

After creation, Okta lands on the application's **General** tab. Record three values and enter them in the SSO form (**Admin settings -> Single sign-on**):

| Okta field                                                                                  | SSO settings field |
| ------------------------------------------------------------------------------------------- | ------------------ |
| Client ID                                                                                   | Client ID          |
| Client Secret                                                                               | Client secret      |
| Okta domain (in the **Sign On** tab as the issuer URL, e.g. `https://your-tenant.okta.com`) | Issuer             |

The client secret is shown once on creation. Enter it in the SSO form; the server seals it at rest with a key derived from `EDR_SECRET_KEY` and never returns it over the API (the field is write-only). There is no env-var or `*_FILE` path for it.

If the client secret leaks, **rotate immediately**: Okta admin console -> Applications -> the EDR app -> **General** -> **Client Credentials** -> **Generate new secret**. Then re-enter it in the UI (**Admin settings -> Single sign-on**); the change applies without a restart. Existing sessions stay valid (sessions are signed with a key derived from `EDR_SECRET_KEY`, not the client secret); only fresh sign-ins use the new secret.

## Configure the EDR server

SSO itself is configured entirely in the UI (above). The only server-side knob OIDC depends on is the deployment root secret, plus the optional session/reauth timeouts:

```bash
EDR_SECRET_KEY=<generate with: openssl rand -hex 32>
```

`EDR_SECRET_KEY` is the server-side deployment root secret, not an Okta artifact, but OIDC will not complete without it: the cookie signing key derived from it signs the state cookie that survives the round-trip to Okta and the session cookie minted on success, and the same key seals the stored client secret at rest. It is required on every boot regardless of OIDC (the host-token pepper also derives from it). Generate it with `openssl rand -hex 32` (any random value of at least 32 bytes works; the config layer rejects shorter ones) and keep it stable, since rotating it invalidates every active session and every host token (and makes the stored client secret undecryptable until re-entered). See [install-server.md](install-server.md#configuration-reference) and [operations.md](operations.md#edr-root-secret) for delivery via the `*_FILE` mount, multi-replica sharing, and rotation.

Optional knobs (defaults shown):

```bash
EDR_SESSION_IDLE_TIMEOUT=8h
EDR_SESSION_ABSOLUTE_TIMEOUT=24h
EDR_REAUTH_WINDOW=30m
```

The requested OIDC scopes are fixed at `openid,email,profile`: enough for the claims the JIT provisioner needs (`sub`, `email`, `name`), with no `groups` until group-to-role mapping ships in a future release. The OIDC state cookie is valid for 5 minutes, long enough for a password manager plus an MFA prompt.

Notes on the optional knobs:

- **JIT provisioning.** JIT is always on in the current release: a first successful sign-in creates a user + identity + role binding at the configured default role. The default role is set in the SSO settings form; the operator-invite flow that would let an admin pre-provision users and turn JIT off is not built yet.
- **Session timeouts.** OIDC-minted sessions slide on every authenticated request up to `EDR_SESSION_ABSOLUTE_TIMEOUT`. The reauth window applies to destructive actions (`host.isolate`, `host.kill_process`, `host.run_script`, `alert.resolve` when severity=critical) and forces a fresh IdP prompt when `last_auth_at` is older than `EDR_REAUTH_WINDOW`.

## Verify

1. Open `https://<edr-host>/ui/login` in a browser that is NOT already signed into Okta.
2. Click **Continue with single sign-on**. The browser bounces to Okta, prompts for the user, and (if MFA is enforced on the tenant) prompts for the second factor.
3. On success, Okta redirects to `/api/auth/callback?...` and the EDR server redirects you to `/ui/`. The top nav shows the signed-in user's email.
4. Open a new browser profile (or incognito) and try a user who is **not** assigned to the application. Okta serves its own access denied page; you never reach the EDR server.

The server emits `auth.oidc.success`, `auth.oidc.failure`, or `auth.oidc.callback.error` audit rows on every flow:

```sql
SELECT id, occurred_at, action, actor_email, payload
FROM audit_events
WHERE action LIKE 'auth.oidc.%'
ORDER BY occurred_at DESC
LIMIT 50;
```

The `payload.reason` column on a failure narrows the cause (`unknown_subject`, `email_conflict`, `state_mismatch`, `exchange_failed`, etc.). Cross-reference with [`threat-model.md`](threat-model.md) for the threats each failure mode covers.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Browser hits Okta then bounces back to `/ui/login?error=invalid_state` | Cookie blocked by browser, or load balancer stripped the `Secure` cookie over plaintext HTTP | Confirm the EDR server is reached over HTTPS end-to-end; the state cookie is `Secure` and the browser drops it on plaintext |
| `error=state_mismatch` | The state cookie was minted by a different EDR instance than the one handling the callback | Pin the load balancer's session affinity, or scale to a single instance for the callback path. The state cookie is HMAC-signed, but each instance reads it from the per-flow cookie value, not a shared store |
| `error=unknown_subject` with JIT enabled | Okta issued a `sub` for a user that the EDR is treating as new (usually a duplicate-user race); check `users` for an earlier row with the same `email` | Delete the orphan row, or disable JIT in the SSO settings and pre-provision the user via SQL |
| `error=email_conflict` | An existing `users` row has the email but is bound to a different OIDC subject (typical of re-tenanted Okta orgs) | Have an admin merge the rows in SQL: update `identities.subject` on the canonical user, delete the duplicate row |
| `error=exchange_failed` | Okta token endpoint unreachable, or client secret rotated without restarting the EDR server | Curl `https://<okta-host>/oauth2/v1/token` from the EDR host; restart the EDR server after a secret rotation |
| Browser sits on Okta and never redirects | Sign-in redirect URI on the Okta app does not exactly match the redirect derived from the stored external URL (`<external-url>/api/auth/callback`) | Compare both for trailing slashes, query strings, scheme, and casing |

## Related docs

- [`breakglass.md`](breakglass.md): the recovery path when SSO is unavailable.
- [`install-server.md`](install-server.md): the rest of the `EDR_*` env vars the server reads at boot.
- [`authz.md`](authz.md): the role matrix and the role JIT-provisioned OIDC users inherit (currently every new identity lands in `analyst`; admins promote from the Users page in Admin settings).
- [`threat-model.md`](threat-model.md): the threat coverage the OIDC + reauth controls close.
