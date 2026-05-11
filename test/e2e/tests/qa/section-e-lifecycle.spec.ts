import { test, expect } from "@playwright/test";
import { openDB, resetDB, mintBootstrapToken } from "../../fixtures/db";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";
import { signInViaDex } from "./_setup";

// Section E: session lifecycle. Requires the dev server started
// with short timeouts so wall-clock test time stays manageable:
//
//   EDR_SESSION_IDLE_TIMEOUT=15s
//   EDR_SESSION_ABSOLUTE_TIMEOUT=30s
//   EDR_BREAKGLASS_SESSION_IDLE_TIMEOUT=8s
//   EDR_BREAKGLASS_SESSION_ABSOLUTE_TIMEOUT=20s
//
// The package.json `qa:e` script orchestrates the restart. Running
// against the default `task dev:server:qa-oidc` (8h idle / 24h
// absolute for OIDC) would make these tests time out trying to
// observe idle expiry.
//
// E.2 (sliding window keeps an active session alive) and E.3
// (absolute timeout overrides active sliding) are DEFERRED here:
// both require the per-request last_seen_at update to fire, but
// sessions.touchThrottle is hardcoded to 1 minute (see
// server/identity/internal/sessions/sessions.go:46), so any idle
// timeout smaller than 60s renders sliding inert (the throttle
// no-ops every touch within the first 60s after sign-in, and the
// session evicts under the small idle cap before the throttle
// clears). To exercise E.2/E.3 properly an operator needs to run
// the dev server with EDR_SESSION_IDLE_TIMEOUT > touchThrottle
// (e.g. 90s) and EDR_SESSION_ABSOLUTE_TIMEOUT comparably bumped —
// at which point the spec's wall clock approaches 3-5 minutes per
// test. Tracked as a follow-up.

const BREAKGLASS_PASSWORD = "qa-section-e-password";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test.describe.serial("qa: Section E — session lifecycle", () => {
  test("E.1 OIDC idle timeout evicts session past the configured window", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      const db = await openDB();
      try {
        await resetDB(db);
      } finally {
        await db.end();
      }
      await signInViaDex(page, "analyst@qa.local");

      // Wait past EDR_SESSION_IDLE_TIMEOUT (15s) without sending any
      // request. The session row's last_seen_at goes stale; the next
      // hit should be evicted.
      await sleep(18_000);
      const resp = await ctx.request.get("/api/session");
      expect(resp.status()).toBe(401);
    } finally {
      await ctx.close();
    }
  });

  test("E.4 break-glass timeouts are tighter than OIDC", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    let va: VirtualAuthenticator | undefined;
    try {
      va = await installVirtualAuthenticator(page);
      const db = await openDB();
      try {
        await resetDB(db);
        const plaintext = await mintBootstrapToken(db);
        await page.goto(`/admin/break-glass/setup?token=${plaintext}`);
        await page.getByLabel(/password/i).fill(BREAKGLASS_PASSWORD);
        await page.getByRole("button", { name: /register security key/i }).click();
        await page.waitForURL(
          (url) =>
            !url.pathname.includes("break-glass") && !url.pathname.includes("login"),
          { timeout: 15_000 },
        );
      } finally {
        await db.end();
      }

      // Wait past EDR_BREAKGLASS_SESSION_IDLE_TIMEOUT (8s). OIDC's
      // 15s would still be alive; the break-glass session must be
      // gone.
      await sleep(11_000);
      const resp = await ctx.request.get("/api/session");
      expect(resp.status()).toBe(401);
    } finally {
      if (va) await uninstallVirtualAuthenticator(va);
      await ctx.close();
    }
  });

  test("E.5 explicit logout via DELETE /api/session is symmetric with login", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      const db = await openDB();
      try {
        await resetDB(db);
      } finally {
        await db.end();
      }
      await signInViaDex(page, "analyst@qa.local");

      const before = await ctx.request.get("/api/session");
      expect(before.status()).toBe(200);

      const logout = await ctx.request.delete("/api/session");
      expect([200, 204]).toContain(logout.status());

      const after = await ctx.request.get("/api/session");
      expect(after.status()).toBe(401);

      // Session row must be deleted (not just cookie cleared).
      const verifyDB = await openDB();
      try {
        const [rows] = (await verifyDB.query(
          `SELECT COUNT(*) AS n FROM sessions
             WHERE user_id = (SELECT id FROM users WHERE email = 'analyst@qa.local')`,
        )) as [Array<{ n: number }>, unknown];
        expect(Number(rows[0].n)).toBe(0);
      } finally {
        await verifyDB.end();
      }
    } finally {
      await ctx.close();
    }
  });
});
