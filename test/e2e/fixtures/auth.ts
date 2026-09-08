// Sign-in helpers for the L4 UI specs. The existing OIDC path (signInViaDex in tests/qa/_setup.ts) requires the dev server to run with
// the dex IdP wired in (task dev:server:qa-oidc) and consumes a slot from the dex JIT-provisioning rate budget; for specs that just
// need "any signed-in admin session," the break-glass path is faster + has no extra-server-process dependency. This helper extracts
// the break-glass ceremony from reauth-modal-retry.spec.ts so the M6 host-list + process-tree specs don't each carry a 30-LOC copy.

import { Page } from "@playwright/test";
import { openDB, resetDB, mintBootstrapToken, forgeAdminSession } from "./db";
import { installVirtualAuthenticator, VirtualAuthenticator } from "./webauthn";

/**
 * BG_PASSWORD is the password registered during break-glass setup. Any string >=12 chars works; this one is shared across the L4
 * specs so test failures don't have to chase the password value across files.
 */
export const BG_PASSWORD = "qa-l4-break-glass-pw";

/**
 * SETUP_REFILL_MS is how long to wait for the setup bucket to yield the TWO tokens a sign-in needs, and SETUP_RETRY_LIMIT bounds
 * the waiting.
 *
 * `/admin/break-glass/setup` is capped globally at DefaultSetupRatePerMin=5 (server/identity/internal/breakglass/ratelimit.go), a
 * token bucket that starts full and refills one token every 12s. One sign-in spends TWO, because `gateSetupRequest` is shared by
 * handleBeginSetup and handleFinishSetup and each calls AllowSetup, so a freshly started server affords exactly two sign-ins
 * before the third has to wait. Measured, not inferred: two specs sign in, the third gets 429.
 *
 * Waiting ONE refill interval is what a first version did and it livelocks. The two halves are gated separately, so an attempt
 * whose begin succeeds and whose finish is denied has still spent a token; wait 13s, gain one token, and the next attempt's begin
 * consumes it again with nothing left for its finish. The loop then never gets ahead of the bucket however many times it runs.
 * Waiting for both tokens at once is what converges, which is why this is two intervals and not one.
 *
 * 26s rather than 24 leaves room for clock granularity. Three retries is 78s, which fits the 90s per-test timeout the config sets
 * for exactly this (hooks share the test's budget), with room for the ceremony itself.
 */
const SETUP_REFILL_MS = 26_000;
const SETUP_RETRY_LIMIT = 3;

/**
 * signInAsAdminViaBreakGlass installs a virtual WebAuthn authenticator, mints a fresh bootstrap-redemption token, walks the
 * /admin/break-glass/setup flow, and returns once the page has redirected to the signed-in admin dashboard. The seeded admin user
 * has super_admin, so any subsequent route the spec navigates to has the broadest possible access.
 *
 * The caller owns:
 *   - resetting the DB before calling (this helper does not call resetDB; specs that want isolation should call it themselves).
 *   - uninstalling the virtual authenticator on test teardown (this helper returns it so the spec's finally{} block can clean up).
 *
 * Why not absorb resetDB here? Because some specs intentionally want pre-existing data from the fixture (e.g. host-list-shows-hosts
 * enrolls hosts BEFORE signing in so they're visible on first render). Forcing a reset would defeat that. Specs that want isolation
 * call resetDB explicitly.
 */
export async function signInAsAdminViaBreakGlass(page: Page): Promise<VirtualAuthenticator> {
  const va = await installVirtualAuthenticator(page);
  for (let attempt = 0; ; attempt++) {
    const limit = watchForSetupRateLimit(page);
    try {
      if (await redeemBootstrapToken(page, limit)) {
        return va;
      }
    } catch (err) {
      if (!limit.seen) {
        throw err;
      }
    } finally {
      limit.stop();
    }
    if (attempt >= SETUP_RETRY_LIMIT) {
      throw new Error(
        `break-glass setup was rate limited (429) on ${SETUP_RETRY_LIMIT + 1} attempts over ` +
          `${((SETUP_RETRY_LIMIT * SETUP_REFILL_MS) / 1000).toFixed(0)}s. The global cap is ` +
          `DefaultSetupRatePerMin=5 with one token refilling every 12s, and one sign-in spends two. ` +
          `Either this phase signs in far more often than the bucket refills, or the cap regressed.`,
      );
    }
    await page.waitForTimeout(SETUP_REFILL_MS);
  }
}

/**
 * redeemBootstrapToken walks one attempt at the redemption ceremony: mint a token, fill the password, register the key, and wait for
 * the redirect to the signed-in dashboard. Waiting on a URL that contains neither break-glass nor login is robust to small route
 * shape changes (e.g. ? param suffixes the server may add).
 *
 * A fresh token per attempt rather than a reused one. A 429 rejects before redemption so the previous token is still live, but
 * minting is one INSERT and reusing it would make a retry depend on that ordering holding.
 */
async function redeemBootstrapToken(page: Page, limit: SetupRateLimitWatch): Promise<boolean> {
  const setupDB = await openDB();
  let plaintext: string;
  try {
    plaintext = await mintBootstrapToken(setupDB);
  } finally {
    await setupDB.end();
  }

  await page.goto(`/admin/break-glass/setup?token=${plaintext}`);
  await page.getByLabel(/password/i).fill(BG_PASSWORD);
  await page.getByRole("button", { name: /register security key/i }).click();

  // The race is HERE, after the form is driven, rather than around the whole ceremony. Abandoning a ceremony mid-fill would leave
  // it typing into the page while the next attempt navigates away, so two attempts would drive one page at once. What is
  // abandoned here is a wait, which mutates nothing.
  const redirected = page
    .waitForURL((url) => !url.pathname.includes("break-glass") && !url.pathname.includes("login"), { timeout: 15_000 })
    .then(() => true);
  // The losing branch still settles, by rejecting on its own timeout long after the race has moved on, and nothing would be
  // listening. The sink keeps that from failing the run; the race still sees the original promise, since catch returns a new one.
  redirected.catch(() => undefined);
  return await Promise.race([redirected, limit.rateLimited.then(() => false)]);
}

/**
 * watchForSetupRateLimit reports a 429 from the setup endpoint, as a flag and as a promise.
 *
 * The 429 is invisible from the page: the ceremony simply never redirects, so it surfaces as a waitForURL timeout that reads like
 * a broken sign-in. The flag tells a rate limit apart from a real break, so a genuine regression still fails on the first attempt
 * rather than being retried into a much slower failure.
 *
 * The promise is what keeps the retry inside Playwright's test budget. Waiting out the ceremony's own 15s navigation timeout
 * before each 13s refill would put a single retry at 28s against a 30s default per-test timeout, so a rate-limited sign-in would
 * fail on the timeout rather than recover, and a second retry could never happen. Racing the ceremony against this promise
 * abandons a rate-limited attempt as soon as the response arrives, which costs milliseconds, so the bounded sequence is paced by
 * the refill wait alone.
 */
interface SetupRateLimitWatch {
  readonly seen: boolean;
  readonly rateLimited: Promise<true>;
  stop: () => void;
}

function watchForSetupRateLimit(page: Page): SetupRateLimitWatch {
  let markSeen: (v: true) => void = () => undefined;
  const rateLimited = new Promise<true>((resolve) => {
    markSeen = resolve;
  });
  const onResponse = (response: { url: () => string; status: () => number }) => {
    if (response.url().includes("/admin/break-glass/setup") && response.status() === 429) {
      state.seen = true;
      markSeen(true);
    }
  };
  const state = {
    seen: false,
    rateLimited,
    stop: () => page.off("response", onResponse),
  };
  page.on("response", onResponse);
  return state;
}

/**
 * resetAndSignIn is the common preface for L4 specs that want a clean DB. Calls resetDB + resetHostData, then
 * signInAsAdminViaBreakGlass, then returns the virtual authenticator for cleanup. Most M6 specs call this in beforeEach; specs that
 * need to seed data BEFORE sign-in call resetDB + their data setup explicitly, then signInAsAdminViaBreakGlass.
 */
export async function resetAndSignIn(page: Page): Promise<VirtualAuthenticator> {
  const db = await openDB();
  try {
    await resetDB(db);
    await resetHostData(db);
  } finally {
    await db.end();
  }
  return signInAsAdminViaBreakGlass(page);
}

/**
 * resetHostData wipes the agent-side tables (the visibility event_queue, processes, hosts, enrollments) and the dependent
 * alert_events / alerts rows. The order respects FK constraints: alert_events references alerts, and alerts references processes, so
 * children first, then parents. event_queue is the visibility work queue (ADR-0015): clearing it stops any leftover queued events from
 * materializing processes/hosts into an "empty state" test after reset. Events themselves live in the ClickHouse archive, which these
 * MySQL-backed UI specs don't read (they assert host/process/alert state), so the archive is intentionally left alone. Tests that want
 * a clean host-list view call this; auth-only specs don't need it (and fixtures/db.ts's resetDB deliberately leaves these tables alone
 * so the existing reauth-modal spec keeps its hosts row available across runs).
 */
export async function resetHostData(db: import("mysql2/promise").Connection): Promise<void> {
  await db.query(`
    DELETE FROM alert_events;
    DELETE FROM alerts;
    DELETE FROM processes;
    DELETE FROM event_queue;
    DELETE FROM hosts;
    DELETE FROM enrollments;
  `);
}

// Re-export from the source module (Sonar S7763: `export { X }` of an imported name should use `export { X } from`).
export { uninstallVirtualAuthenticator } from "./webauthn";

/**
 * signInAsAdminViaForgedSession puts the page into a signed-in super_admin session without walking any ceremony: it inserts the
 * session row the server would have inserted and sets the cookie the server would have set.
 *
 * Use this for a spec that needs "any signed-in admin" and asserts nothing about HOW the session was obtained. That is most of
 * them. Specs whose SUBJECT is authentication keep the real path: `tests/auth/break-glass-setup.spec.ts` and
 * `break-glass-login.spec.ts` walk the ceremony end to end, and `reauth-modal-retry` and `session-lifecycle` depend on genuine
 * session state. Nothing here replaces those, and it must not: the ceremony has to stay exercised somewhere or forging would
 * silently become the only thing tested.
 *
 * Why it is worth the fixture: `/admin/break-glass/setup` is capped at five submissions per minute globally and one sign-in
 * spends two, so a suite that signs in ten times waits on a token bucket rather than on the product. Measured on a lane-B dev
 * server, about three of Phase 8's 4.8 minutes was that wait.
 *
 * The verification is the point of the last few lines, not a formality. A forged row that authenticates but carries the wrong
 * shape (no CSRF token, a stale `last_auth_at`, a missing role binding) would let a spec pass against a session the product never
 * issues, and the failure would surface later as an unrelated-looking authorization bug. Reading `/api/session` once costs one
 * request and checks the whole chain: cookie encoding, digest agreement, expiry, and that the session resolves to a principal
 * carrying a CSRF token.
 */
export async function signInAsAdminViaForgedSession(page: Page): Promise<void> {
  const db = await openDB();
  try {
    const token = await forgeAdminSession(db);
    // Scoped by URL rather than by a hardcoded domain: the suite runs against whichever lane E2E_PORT names, and a cookie set on
    // the wrong origin would simply not be sent, surfacing as an unauthenticated page rather than as a fixture error.
    await page.context().addCookies([
      {
        name: "edr_session",
        value: token,
        url: baseURLFor(),
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
    ]);
  } finally {
    await db.end();
  }

  const resp = await page.request.get("/api/session");
  if (resp.status() !== 200) {
    throw new Error(`signInAsAdminViaForgedSession: /api/session returned ${resp.status()}, so the forged session is not usable`);
  }
  const body = (await resp.json()) as { csrf_token?: string };
  if (!body.csrf_token) {
    throw new Error("signInAsAdminViaForgedSession: session resolved but carries no CSRF token; state-changing requests would fail");
  }
}

/**
 * baseURLFor recovers the origin the suite is running against. Playwright resolves relative navigations against the config's
 * baseURL but does not expose it on Page, and `page.url()` is `about:blank` before the first navigation, which is exactly when
 * this fixture runs. E2E_PORT is the same variable the config reads, and assertLaneEnv already requires it to be set together
 * with E2E_DB, so reading it here cannot point the cookie at a different lane from the database the row was written to.
 */
function baseURLFor(): string {
  return `https://localhost:${process.env.E2E_PORT ?? "8088"}`;
}
