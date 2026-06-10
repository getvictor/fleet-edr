// Sign-in helpers for the L4 UI specs. The existing OIDC path (signInViaDex in tests/qa/_setup.ts) requires the dev server to run with
// the dex IdP wired in (task dev:server:qa-oidc) and consumes a slot from the dex JIT-provisioning rate budget; for specs that just
// need "any signed-in admin session," the break-glass path is faster + has no extra-server-process dependency. This helper extracts
// the break-glass ceremony from reauth-modal-retry.spec.ts so the M6 host-list + process-tree specs don't each carry a 30-LOC copy.

import { Page } from "@playwright/test";
import { openDB, resetDB, mintBootstrapToken } from "./db";
import { installVirtualAuthenticator, VirtualAuthenticator } from "./webauthn";

/**
 * BG_PASSWORD is the password registered during break-glass setup. Any string >=12 chars works; this one is shared across the L4
 * specs so test failures don't have to chase the password value across files.
 */
export const BG_PASSWORD = "qa-l4-break-glass-pw";

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
  // The redemption ceremony auto-signs the admin in and lands on the dashboard. Waiting on URL not containing break-glass / login is
  // robust to small route shape changes (e.g. ? param suffixes the server may add).
  await page.waitForURL(
    (url) => !url.pathname.includes("break-glass") && !url.pathname.includes("login"),
    { timeout: 15_000 },
  );
  return va;
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
 * resetHostData wipes the agent-side tables (events, processes, hosts, enrollments) and the dependent alert_events / alerts rows.
 * The order respects FK constraints: alert_events references both alerts and events, and alerts references processes, so children
 * first, then parents. Tests that want a clean host-list view call this; auth-only specs don't need it (and fixtures/db.ts's resetDB
 * deliberately leaves these tables alone so the existing reauth-modal spec keeps its hosts row available across runs).
 */
export async function resetHostData(
  db: import("mysql2/promise").Connection,
): Promise<void> {
  await db.query(`
    DELETE FROM alert_events;
    DELETE FROM alerts;
    DELETE FROM processes;
    DELETE FROM events;
    DELETE FROM hosts;
    DELETE FROM enrollments;
  `);
}

// Re-export from the source module (Sonar S7763: `export { X }` of an imported name should use `export { X } from`).
export { uninstallVirtualAuthenticator } from "./webauthn";
