import { test, expect } from "../../fixtures/test";
import { openDB, resetDB } from "../../fixtures/db";

// SSO sign-in via the local dex IdP (started by `task qa:up`). The
// four pre-provisioned dex users (analyst@qa.local, senior@qa.local,
// auditor@qa.local, admin@qa.local) all share password
// `qa-password-123`. First sign-in JIT-provisions the user as
// `analyst` per docs/authz.md; the role-matrix specs promote via SQL
// to exercise the other tiers.
test.describe("oidc sign-in via local dex", () => {
  const password = "qa-password-123";

  test.beforeEach(async () => {
    const db = await openDB();
    try {
      await resetDB(db);
    } finally {
      await db.end();
    }
  });

  // spec:web-ui/authenticated-entry-to-the-application/successful-login-routes-to-the-home-view
  test("analyst JIT-provisions on first sign-in + lands at /ui/", async ({
    page,
  }) => {
    await page.goto("/ui/login");
    await page.getByRole("button", { name: /continue with single sign-on/i }).click();
    await page.waitForURL(/localhost:5556\/dex/);

    // Dex's login form's labels aren't <label for="...">-associated,
    // so address inputs by name. The form posts back to dex which
    // 302s to /api/auth/callback?code=... when credentials match.
    await page.locator('input[name="login"]').fill("analyst@qa.local");
    await page.locator('input[name="password"]').fill(password);
    await page.getByRole("button", { name: /login/i }).click();

    // Dex redirects back to /api/auth/callback?code=...&state=...
    // The EDR exchanges the code, JIT-provisions the user, mints
    // a session, and redirects to /ui/.
    await page.waitForURL(
      (url) =>
        url.host === "localhost:8088" &&
        !url.pathname.includes("login") &&
        !url.pathname.includes("break-glass"),
      { timeout: 30_000 },
    );

    // The JIT-provisioned user should be visible in the DB with
    // role = analyst per docs/authz.md's DefaultJITRole.
    const db = await openDB();
    try {
      const [rows] = (await db.query(
        `SELECT u.email, i.provider, rb.role_id
         FROM users u
         JOIN identities i ON i.user_id = u.id
         JOIN role_bindings rb ON rb.user_id = u.id
         WHERE u.email = 'analyst@qa.local'`,
      )) as [Array<{ email: string; provider: string; role_id: string }>, unknown];
      expect(rows).toHaveLength(1);
      expect(rows[0].provider).toBe("oidc");
      expect(rows[0].role_id).toBe("analyst");
    } finally {
      await db.end();
    }

    // The analyst role does NOT grant audit.read, so the
    // audit-events endpoint should 403 with no_matching_rule.
    const audit = await page.request.get("/api/audit-events");
    expect(audit.status()).toBe(403);
    expect(audit.headers()["x-edr-authz-reason"]).toBe("no_matching_rule");
  });

  test("repeat sign-in reuses the existing user (no duplicate rows)", async ({
    page,
  }) => {
    async function signInViaDex() {
      await page.goto("/ui/login");
      await page.getByRole("button", { name: /continue with single sign-on/i }).click();
      await page.waitForURL(/localhost:5556\/dex/);
      await page.locator('input[name="login"]').fill("analyst@qa.local");
      await page.locator('input[name="password"]').fill(password);
      await page.getByRole("button", { name: /login/i }).click();
      await page.waitForURL(
        (url) =>
          url.host === "localhost:8088" &&
          !url.pathname.includes("login") &&
          !url.pathname.includes("break-glass"),
        { timeout: 30_000 },
      );
    }

    await signInViaDex();
    await page.request.delete("/api/session");
    await signInViaDex();

    const db = await openDB();
    try {
      const [rows] = (await db.query(
        "SELECT COUNT(*) AS n FROM users WHERE email = 'analyst@qa.local'",
      )) as [Array<{ n: number }>, unknown];
      expect(Number(rows[0].n)).toBe(1);
    } finally {
      await db.end();
    }
  });
});
