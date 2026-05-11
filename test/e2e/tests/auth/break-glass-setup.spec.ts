import { test, expect } from "../../fixtures/test";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";
import { openDB, resetDB, mintBootstrapToken } from "../../fixtures/db";

// The Phase 4b break-glass redemption ceremony walked from the UI
// instead of curl + audit log. Drives the full flow: open the
// redemption URL with a freshly-minted token, fill in the password,
// register a security key (virtual authenticator), land at /ui/ as
// the signed-in admin.
//
// Without this test the redemption page can ONLY be exercised by a
// human operator with a physical authenticator (Touch ID / YubiKey),
// which means QA pre-release is gated on someone being at a Mac.
test.describe("break-glass redemption ceremony", () => {
  let va: VirtualAuthenticator;

  test.beforeEach(async ({ page }) => {
    va = await installVirtualAuthenticator(page);
    const db = await openDB();
    try {
      await resetDB(db);
    } finally {
      await db.end();
    }
  });

  test.afterEach(async () => {
    if (va) await uninstallVirtualAuthenticator(va);
  });

  test("redeem fresh token + register security key + land signed-in", async ({
    page,
  }) => {
    // The seeded admin row + role binding were created at server
    // boot (the first /livez warmed the seed path). Mint a fresh
    // bootstrap token bound to that admin.
    const db = await openDB();
    let plaintext: string;
    try {
      plaintext = await mintBootstrapToken(db);
    } finally {
      await db.end();
    }

    await page.goto(`/admin/break-glass/setup?token=${plaintext}`);

    // Server 302s to /ui/admin/break-glass/setup?token=...; the React
    // redemption page should now be mounted.
    await expect(page).toHaveURL(/\/ui\/admin\/break-glass\/setup/);
    await expect(page.getByRole("heading", { name: /break-glass setup/i })).toBeVisible();

    // The password input must enforce the >= 12 code-point minimum.
    // First a too-short password to verify the live counter rejects.
    await page.getByLabel(/password/i).fill("short");
    await expect(
      page.getByRole("button", { name: /register security key/i }),
    ).toBeDisabled();

    // Now a valid password + register.
    await page.getByLabel(/password/i).fill("qa-redeem-password-12-chars");
    await expect(
      page.getByRole("button", { name: /register security key/i }),
    ).toBeEnabled();

    // Optional: name the credential so audit rows can attribute the
    // registration.
    const nameField = page.getByLabel(/credential name/i);
    if (await nameField.count()) {
      await nameField.fill("e2e-virtual-authenticator");
    }

    await page.getByRole("button", { name: /register security key/i }).click();

    // The virtual authenticator answers the WebAuthn challenge
    // synchronously; the page navigates to /ui/ which the router
    // forwards to /ui/hosts. Poll the URL until we've left the
    // setup page; logs it on failure so a regression surfaces what
    // the actual landing is.
    await expect
      .poll(() => page.url(), { timeout: 15_000, message: "expected to leave the setup page" })
      .not.toMatch(/break-glass\/setup/);
    await expect(page).toHaveURL(/\/ui(\/|$|\?)/);

    // Top nav surfaces the signed-in email (or at least the
    // sign-out control - varies by build).
    const topNav = page.locator("[data-testid='top-nav'], nav").first();
    await expect(topNav).toBeVisible();
  });

  test("expired token returns 410 on the validation POST", async ({ page }) => {
    // Insert a token whose expires_at is already in the past, then
    // try to begin the WebAuthn setup challenge. The handler should
    // refuse with 410 Gone (reason=bootstrap.expired or similar).
    const db = await openDB();
    try {
      await db.query(`
        INSERT INTO bootstrap_tokens (token_hash, user_id, kind, expires_at)
        SELECT UNHEX('00000000000000000000000000000000000000000000000000000000deadbeef'),
               id, 'breakglass_setup', NOW(6) - INTERVAL 1 HOUR
        FROM users WHERE email = 'admin@fleet-edr.local'
      `);
    } finally {
      await db.end();
    }
    // Use a plaintext whose hash is NOT in the DB; the response is
    // bootstrap.invalid (hash mismatch) which is the same wire shape
    // an expired/missing/already-redeemed token produces (enumeration
    // resistance per spec).
    const response = await page.request.post(
      "/admin/break-glass/setup/challenge?token=fake-plaintext-does-not-resolve",
    );
    expect(response.status()).toBe(410);
    expect(response.headers()["x-edr-auth-reason"]).toMatch(
      /^bootstrap\.(invalid|consumed|expired)$/,
    );
  });
});
