import { test, expect } from "../../fixtures/test";
import { openDB, resetDB } from "../../fixtures/db";

// With EDR_OIDC_ALLOW_JIT_PROVISIONING=0 the OIDC callback refuses
// to create a new users row for a `sub` it doesn't already know,
// emits an oidc.unknown_subject audit row, and bounces the operator
// to /login?error=unknown_subject. Run ONLY against a dev server
// started with that env set; otherwise admin@qa.local will
// JIT-provision as analyst and the test will pass for the wrong
// reason. The package.json `qa:jit-off` script orchestrates the
// restart.

const dexPassword = "qa-password-123";

test.describe("OIDC unknown subject rejected when JIT is disabled", () => {
  test("sign in with admin@qa.local (never seen) returns oidc.unknown_subject", async ({
    page,
  }) => {
    // Reset DB so admin@qa.local truly doesn't exist (the other
    // three dex users may have been JIT'd earlier; admin@qa.local
    // is reserved for this test).
    const db = await openDB();
    try {
      await resetDB(db);
    } finally {
      await db.end();
    }

    await page.goto("/ui/login");
    await page.getByRole("button", { name: /continue with single sign-on/i }).click();
    await page.waitForURL(/localhost:5556\/dex/);
    await page.locator('input[name="login"]').fill("admin@qa.local");
    await page.locator('input[name="password"]').fill(dexPassword);
    await page.getByRole("button", { name: /login/i }).click();

    // The handler 302s the user back to /login?error=unknown_subject.
    // The server's `/` catchall redirects /login to /ui/ and drops
    // the query, so the visible URL after navigation may not show
    // the error fragment — but the audit row is authoritative.
    await page.waitForURL((url) => url.host === "localhost:8088", {
      timeout: 30_000,
    });

    // No row should have been created for admin@qa.local.
    const verifyDB = await openDB();
    try {
      const [users] = (await verifyDB.query(
        "SELECT id FROM users WHERE email = ?",
        ["admin@qa.local"],
      )) as [Array<{ id: number }>, unknown];
      expect(users).toHaveLength(0);

      // Audit row records the precise reason.
      const [rows] = (await verifyDB.query(
        `SELECT JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reason')) AS reason
           FROM audit_events
          WHERE action = 'auth.oidc.failure'
          ORDER BY id DESC LIMIT 1`,
      )) as [Array<{ reason: string }>, unknown];
      expect(rows).toHaveLength(1);
      expect(rows[0].reason).toBe("oidc.unknown_subject");
    } finally {
      await verifyDB.end();
    }
  });
});
