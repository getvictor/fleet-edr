import { test, expect } from "@playwright/test";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";
import { openDB, resetDB, mintBootstrapToken } from "../../fixtures/db";

// Section A.4 of the manual QA plan: a freshly-redeemed admin can
// sign back in via /admin/break-glass with email + password +
// virtual-authenticator assertion. End-to-end registration first
// (so the credential row exists), then logout, then login.
test.describe("break-glass day-to-day login", () => {
  let va: VirtualAuthenticator;
  const password = "qa-login-password-12-chars";

  test.beforeEach(async ({ page }) => {
    va = await installVirtualAuthenticator(page);
    const db = await openDB();
    try {
      await resetDB(db);
      const plaintext = await mintBootstrapToken(db);
      // Walk the redemption ceremony so a credential row exists.
      await page.goto(`/admin/break-glass/setup?token=${plaintext}`);
      await page.getByLabel(/password/i).fill(password);
      const name = page.getByLabel(/credential name/i);
      if (await name.count()) await name.fill("e2e-day-to-day-login");
      await page
        .getByRole("button", { name: /register security key/i })
        .click();
      // The redemption URL itself is /ui/admin/break-glass/setup,
      // so a prefix-match regex on /ui/ fires before the ceremony
      // even starts. Require the URL to no longer contain
      // "break-glass" (the landing page is /ui/ or /ui/hosts).
      await page.waitForURL((url) => !url.pathname.includes("break-glass"), {
        timeout: 15_000,
      });
      // Verify the credential actually persisted before signing out;
      // a silent failure here was the bug that surfaced on first
      // iteration. The redemption flow's FinishSetup uses a tx; if
      // it rolled back, the URL would still flip to /ui/ but no
      // webauthn_credentials row would exist.
      const [credRows] = (await db.query(
        "SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = (SELECT id FROM users WHERE email = 'admin@fleet-edr.local')",
      )) as [Array<{ n: number }>, unknown];
      if (Number(credRows[0].n) !== 1) {
        throw new Error(
          `redemption fixture: expected 1 webauthn credential, got ${credRows[0].n}`,
        );
      }
      // Sign out so the next step starts unauthenticated.
      await page.request.delete("/api/session");
    } finally {
      await db.end();
    }
  });

  test.afterEach(async () => {
    if (va) await uninstallVirtualAuthenticator(va);
  });

  test("login with correct password + assertion lands at /ui/", async ({
    page,
  }) => {
    await page.goto("/ui/login");
    await page.getByRole("link", { name: /break-glass/i }).click();

    await page.getByLabel(/email/i).fill("admin@fleet-edr.local");
    await page.getByLabel(/password/i).fill(password);
    await page.getByRole("button", { name: /sign in with security key/i }).click();

    // Same prefix-match trap: /ui/login itself matches /ui/, so a
    // plain regex would fire before login finishes. Wait until we
    // leave the login page (URL no longer contains "break-glass" or
    // "login").
    await page.waitForURL(
      (url) =>
        !url.pathname.includes("break-glass") &&
        !url.pathname.includes("login"),
      { timeout: 15_000 },
    );
    // /api/hosts should be reachable now (super_admin grants
    // host.read; the seed bug fix at commit 9115018 ensured the
    // role binding lands at seed time).
    const hosts = await page.request.get("/api/hosts");
    expect(hosts.status()).toBe(200);
  });

  // Wrong-password / unknown-email enumeration-resistance is covered
  // exhaustively at the Go layer in
  // server/identity/internal/breakglass/handler_test.go. A UI-layer
  // version is desirable but the dynamic error-text shape (varies
  // by browser, by phase) makes it brittle as a v1 E2E. Reintroduce
  // here once the UI's error-rendering contract is pinned.
});
