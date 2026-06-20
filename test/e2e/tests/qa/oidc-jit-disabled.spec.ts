import { test, expect } from "../../fixtures/test";
import { openDB, resetDB } from "../../fixtures/db";

// When JIT provisioning is disabled the OIDC callback refuses to create a new users row for a `sub` it doesn't already know, emits an
// oidc.unknown_subject audit row, and bounces the operator to /login?error=unknown_subject.
//
// JIT is DB-governed (issue #375): EDR_OIDC_ALLOW_JIT_PROVISIONING only seeds the stored oidc_config on first boot and is inert once a
// row exists, so this test disables JIT by writing jit_enabled = 0 directly to the stored config (the provisioner reads it per OIDC
// callback, so it applies without a restart). resetDB() intentionally does not touch oidc_config, so the flag is persistent shared
// state across specs; beforeAll captures the prior value and afterAll restores it exactly, leaving the suite's SSO posture unchanged.

const dexPassword = "qa-password-123";

test.describe("OIDC unknown subject rejected when JIT is disabled", () => {
  let originalJIT = 1;

  test.beforeAll(async () => {
    const db = await openDB();
    try {
      const [rows] = (await db.query("SELECT jit_enabled FROM oidc_config WHERE id = 1")) as [Array<{ jit_enabled: number }>, unknown];
      if (rows.length > 0) {
        originalJIT = rows[0].jit_enabled;
      }
      await db.query("UPDATE oidc_config SET jit_enabled = 0");
    } finally {
      await db.end();
    }
  });

  test.afterAll(async () => {
    const db = await openDB();
    try {
      await db.query("UPDATE oidc_config SET jit_enabled = ?", [originalJIT]);
    } finally {
      await db.end();
    }
  });

  test("sign in with admin@qa.local (never seen) returns oidc.unknown_subject", async ({ page }) => {
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
    // the error fragment. The audit row, however, is authoritative.
    await page.waitForURL((url) => url.host === "localhost:8088", {
      timeout: 30_000,
    });

    // No row should have been created for admin@qa.local.
    const verifyDB = await openDB();
    try {
      const [users] = (await verifyDB.query("SELECT id FROM users WHERE email = ?", ["admin@qa.local"])) as [
        Array<{ id: number }>,
        unknown,
      ];
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
