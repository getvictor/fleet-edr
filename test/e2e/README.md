# End-to-end test suite

Playwright-based E2E tests that drive Chrome against a running EDR
server. Sister to `test/integration/` (Go cross-context) and
`test/arch/` (architecture invariants); covers everything in between
- the UI + server wire shapes + the network-attached auth flows that
Go integration tests skip because they need a real browser.

Owns its own `package.json` so the UI's `ui/package.json` stays lean
on test-only dependencies.

## Scope today

- `tests/auth/break-glass-setup.spec.ts` - WebAuthn redemption
  ceremony with a virtual authenticator; covers the UI-driven
  redemption path without a physical Touch ID.
- `tests/auth/break-glass-login.spec.ts` - day-to-day break-glass
  login (registration first so a credential row exists, then logout,
  then sign-back-in).
- `tests/auth/oidc-login.spec.ts` - SSO sign-in against the local
  dex (started by `task qa:up`): first-login JIT-provisions, repeat
  sign-in reuses the existing user row.
- `tests/qa/` - operator-facing flows on the running server: role
  matrix + reauth gate + audit-events filters + OIDC state-cookie
  tampering, break-glass login failure-reason + IP allowlist + per-
  IP rate limit, OIDC JIT-off rejection, reauth-modal retry (OIDC +
  break-glass), and session lifecycle (idle eviction + symmetric
  logout). Run via `npm run qa` (default-env specs) plus
  `qa:allowlist` / `qa:jit-off` / `qa:rate-limit` / `qa:lifecycle`
  against env-restarted servers; `scripts/test-e2e-coverage.sh`
  orchestrates the full pipeline with coverage.

## Scope ahead

The structure is built for the wave-2 ambition: cover the major
operator-facing flows (hosts list, alerts, policy, isolate, audit
read) plus the agent enrollment + event-ingestion path with a real
or fake host fixture. The test/e2e/ root is the home; group by
feature under `tests/` (e.g., `tests/hosts/`, `tests/alerts/`,
`tests/agent/`, etc.).

## Setup

One-time:

```sh
task test:e2e:install   # installs Playwright + Chromium (~300 MB)
```

Or directly:

```sh
cd test/e2e
npm install
npx playwright install --with-deps chromium
```

## Running

Make sure the qa stack is up (dex required for the OIDC tests):

```sh
task qa:up
```

Then:

```sh
task test:e2e            # headless, all tests
cd test/e2e && npm run test:headed  # watch the browser
cd test/e2e && npm run test:debug   # Playwright inspector
cd test/e2e && npm run report       # show last HTML report
```

Playwright's `webServer` config auto-starts `task dev:server:qa-oidc`
when no server is bound to :8088. If you already have `task
dev:server:qa-oidc` running, Playwright reuses it.

## WebAuthn virtual authenticator

`fixtures/webauthn.ts` wires a CTAP2 virtual authenticator into the
Chrome DevTools Protocol session. Once installed,
`navigator.credentials.create()` / `.get()` calls on the page route
through the virtual authenticator instead of real hardware. Same
mechanism Chrome's DevTools "WebAuthn" panel exposes manually.

`automaticPresenceSimulation: true` means the authenticator answers
every challenge without simulating a fingerprint prompt - tests stay
deterministic.

## DB state

Each test resets the operator-side tables (users beyond the seeded
admin, sessions, webauthn_credentials, role_bindings, identities,
audit_events, bootstrap_tokens) in its beforeEach. The seeded admin
row stays so the boot path's seed step doesn't re-fire mid-test. See
`fixtures/db.ts`.

`workers: 1` is set in `playwright.config.ts` because the tests share
one MySQL instance; raising it requires per-test DB isolation.

## CI

Not wired into CI yet (issue #116 covers the GH Actions integration).
The local-run path is enough for the wave-1 ship; CI integration
follows once the wave-2 test surface stabilizes.
