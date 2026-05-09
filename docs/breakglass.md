# Break-glass admin

The break-glass account is the single emergency path into the EDR
server when SSO is unavailable or has not been configured. It uses
**password + WebAuthn** with no fallback factor; there is no SMS / TOTP
recovery in v1. Lose the security key and recovery requires a
DB-level intervention documented below.

The seeded break-glass account email is `admin@fleet-edr.local`.

## First-boot redemption

`cmd/main` prints a redemption banner to stderr on first boot if no
WebAuthn credential is yet registered against the canonical
break-glass admin row. The output is one block, one shot:

```text
================================================================
BREAK-GLASS ADMIN SETUP (one-shot redemption URL - open in a browser)
  Email: admin@fleet-edr.local
  URL:   https://<your-host>/admin/break-glass/setup?token=<plaintext>
  TTL:   1h0m0s
================================================================
```

The TTL defaults to one hour and is configurable via
`EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL` (Go duration string). The
banner is idempotent: it re-prints on every restart until the
operator redeems the token, and is silent thereafter (the server
checks for an existing WebAuthn credential at boot).

### Steps

1. Open the URL in the browser of the workstation that will hold
   the security key. The server 302s to `/ui/admin/break-glass/setup`
   (the React redemption page) preserving the `?token=` query.
2. Set a password. The wave-1 policy is **length-only ≥ 12 Unicode
   code points** - the page shows a live counter against the
   minimum. Complexity is the operator's choice; the server does
   not score against a dictionary or zxcvbn.
3. Optionally enter a credential name (e.g. "yubikey-blue"). This
   is metadata only - the WebAuthn ceremony and the chokepoint
   don't read it.
4. Click "Register security key". The browser prompts for the
   authenticator (Touch ID, YubiKey, Windows Hello, etc.).
5. On success the page navigates to `/ui/` signed in as the
   break-glass admin. The token is consumed atomically with the
   credential write - re-using the URL is a 410 Gone.

### What's persisted

- `users` row for `admin@fleet-edr.local` with the password's
  Argon2id hash + salt.
- `webauthn_credentials` row binding the registered authenticator
  to the user.
- `bootstrap_tokens.redeemed_at` set on the row that minted the URL.
- One `auth.breakglass.bootstrap` audit row recording the successful
  redemption (token issuance itself is not audited). The next
  `auth.breakglass.success` row lands the first time the operator
  signs in via the day-to-day login flow.

If the page errors mid-ceremony (browser closed, USB disconnected),
the token is **not** consumed - retry on the same URL until the TTL
expires or the page completes the redemption transaction.

## Day-to-day login

The login flow is the same shape as redemption minus the registration
step:

1. From `/ui/login`, click the "Break-glass login" footer link.
2. Enter the email + password.
3. Click "Sign in with security key" → the browser prompts the
   authenticator → server validates the signed assertion + the
   password.
4. On success, the page navigates to `/ui/`.

Failure modes (unknown email / wrong password / wrong assertion /
no credentials / sign-count regression) collapse to a single
`invalid_credentials` 401 on the wire so an attacker cannot
enumerate accounts. The audit row records the precise reason
(`auth.breakglass.failure` with `payload.reason`).

## Registering a second security key

Wave 1 redeems exactly one credential per bootstrap token. To add
a second key (recommended for redundancy - losing the only
credential triggers the recovery path below), issue a fresh
bootstrap token via SQL and walk the redemption flow against the
already-redeemed account:

1. Generate the plaintext + hash:
   ```bash
   PLAINTEXT=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
   echo -n "$PLAINTEXT" | sha256sum
   ```
   The first command produces the URL-safe base64 plaintext; the
   second emits the hex of its SHA-256. Convert the hex to the
   `VARBINARY(32)` MySQL needs - see the SQL below.

2. Insert the bootstrap token row:
   ```sql
   INSERT INTO bootstrap_tokens (token_hash, user_id, kind, expires_at)
   VALUES (
     UNHEX('<sha256-hex-from-step-1>'),
     (SELECT id FROM users WHERE email = 'admin@fleet-edr.local'),
     'breakglass_setup',
     NOW(6) + INTERVAL 1 HOUR
   );
   ```

3. Construct the redemption URL: `https://<host>/admin/break-glass/setup?token=<plaintext-from-step-1>`.

4. Visit the URL on the workstation that holds the second key.
   Re-enter the same password (the redemption flow validates it
   against the existing hash; passing a different password rejects
   the redemption).

5. Complete the WebAuthn ceremony with the second key. The new
   credential row is appended to `webauthn_credentials`; both
   credentials are now valid for login (the chokepoint accepts an
   assertion from any registered credential on the user).

The redemption happens against the same `users.id` - there's no
separate "second admin" row. Audit log shows the same shape as the
first redemption.

## Lost-credential recovery

If every registered security key is lost, the only path back in is
DB-level. Restrict DB write credentials to the operator authorized
to recover break-glass - anyone with INSERT on `bootstrap_tokens`
can mint a recovery URL.

1. SSH to the host running the EDR server.

2. Connect to MySQL:
   ```bash
   mysql -h 127.0.0.1 -P 3306 -u edr edr
   ```

3. Optionally remove the lost credential(s) so the assertion list
   the page presents is current. NOT required - a credential the
   operator no longer holds can't sign anyway - but it cleans up
   the audit footprint:
   ```sql
   DELETE FROM webauthn_credentials
   WHERE user_id = (SELECT id FROM users WHERE email = 'admin@fleet-edr.local');
   ```

4. Issue a fresh bootstrap token following the steps in the
   previous section. The redemption flow re-registers a credential
   alongside any that survived the DELETE.

5. Visit the redemption URL with the replacement security key.
   Use the existing password - the redemption validates against
   the stored hash. To rotate the password too, run a fresh
   Argon2id hash via the `users` package's helper or change it
   directly in SQL **before** redeeming (the redemption path
   compares the supplied password to the stored hash; a mismatch
   is a redemption failure).

The operator runbook for credential loss should document who has
SSH + MySQL access and rotate that list when staff change.

## Audit trail

| Action | When |
|---|---|
| `auth.breakglass.bootstrap` | Successful redemption: the operator's password + authenticator are now persisted and the token row has been marked `redeemed_at`. Token issuance itself (banner re-print, manual recovery insert) is not audited. |
| `auth.breakglass.success` | Successful day-to-day login (POST `/admin/break-glass`). The redemption flow does not emit this row directly; the next login does. |
| `auth.breakglass.failure` | Any rejection: wrong password, wrong assertion, no credentials, sign-count regression, expired token, redeemed token. `payload.reason` carries the precise wire reason. |

To review the full break-glass timeline:

```sql
SELECT id, occurred_at, action, actor_email, payload
FROM audit_events
WHERE action LIKE 'auth.breakglass.%'
ORDER BY occurred_at DESC
LIMIT 100;
```

## Operational policy

- **Bootstrap-token TTL.** Default 1h. A leaked banner inside the
  TTL is a real risk - the URL is a one-shot bearer credential.
  Treat the stderr banner like a temporary password: copy it,
  redeem it, and don't paste it into chat.
- **Allowlist.** Set `EDR_BREAKGLASS_IP_ALLOWLIST` to a CIDR list
  the operator's bastion is in. Off-allowlist callers see a
  generic 404 - the path's existence is concealed.
- **Rate limits.** Per-IP and per-email limits gate brute-force
  attempts on the login flow; both produce 429 + `Retry-After`.
  Tunable via the breakglass package's options if a deployment's
  pattern needs adjustment.
- **No fallback factor.** v1 ships with no SMS / TOTP recovery by
  design - the WebAuthn-mandatory model is what makes the
  break-glass account phishing-resistant. Recovery via the SQL path
  above is the only escape hatch.

## Related docs

- `docs/authz.md` - the role matrix the break-glass admin lands in
  (super_admin) and the SQL pattern for binding other roles.
- `docs/install-server.md` - the env vars (`EDR_BREAKGLASS_*`) the
  server reads at boot.
- `docs/threat-model.md` - the threat coverage the WebAuthn-
  mandatory break-glass control closes.
