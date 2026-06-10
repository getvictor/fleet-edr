import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/test";
import {
  openDB,
  resetDB,
  mintBootstrapToken,
  promote,
  seedCriticalAlert,
} from "../../fixtures/db";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";
import { signInViaDex } from "./_setup";

// expectAlertResolvedAndAudited asserts the post-resolve invariants
// the two reauth-modal tests share: the operator-visible row
// vanishes from the open-status filter, the alert row is `resolved`
// in MySQL, and exactly one `authz.alert.resolve` audit row was
// emitted with allow=true + reason=granted. Extracted so the two
// tests don't carry a 29-line duplicate of the same SQL + assertion
// block (Sonar new-code duplication gate fires above 3%).
async function expectAlertResolvedAndAudited(
  page: Page,
  title: string,
  alertId: number,
): Promise<void> {
  await expect(page.getByText(title)).toBeHidden({ timeout: 10_000 });

  const verifyDB = await openDB();
  try {
    const [rows] = (await verifyDB.query(
      "SELECT status FROM alerts WHERE id = ?",
      [alertId],
    )) as [Array<{ status: string }>, unknown];
    expect(rows[0].status).toBe("resolved");

    const [auditRows] = (await verifyDB.query(
      `SELECT JSON_UNQUOTE(JSON_EXTRACT(payload, '$.allow')) AS allow_,
              JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reason')) AS reason
         FROM audit_events
        WHERE action = 'authz.alert.resolve'
          AND target_id = ?
        ORDER BY id DESC LIMIT 1`,
      [String(alertId)],
    )) as [Array<{ allow_: string; reason: string }>, unknown];
    expect(auditRows).toHaveLength(1);
    expect(auditRows[0].allow_).toBe("true");
    expect(auditRows[0].reason).toBe("granted");
  } finally {
    await verifyDB.end();
  }
}

// Reauth-modal retry after a stale session denies a destructive
// action. The chokepoint's reauth gate fires for alert.resolve on
// critical-severity alerts (per
// server/identity/internal/authz/policy/edr.rego#L81-82), so each
// test seeds one critical alert + ages the session via SQL to force
// the 403 reauth_required.
//
// Covers BOTH wire variants the ReauthModal dispatches on:
//   - OIDC (full-page navigate to /api/auth/login?reauth=1, walk dex
//     re-auth, return to the page; operator re-clicks the action)
//   - Break-glass (inline modal: password + WebAuthn ceremony via
//     /api/auth/reauth; useReauthRetry's hook auto-fires the original
//     mutation once the modal resolves true)
//
// Runs against the default dev server with no env overrides. The
// break-glass test burns one global break-glass-setup token
// (DefaultSetupRatePerMin = 5/min); this file is sized to fit
// alongside the other default-env qa specs without tripping that
// rate limit.

const DEX_PASSWORD = "qa-password-123";
const BG_PASSWORD = "qa-reauth-modal-breakglass-password";
const TEST_HOST_ID = "qa-reauth-modal-host";
const TEST_RULE_ID = "qa-reauth-modal-rule-critical";

test.describe.serial("reauth modal retry after stale-session denial", () => {
  // beforeAll JIT-provisions senior@qa.local + promotes them to
  // senior_analyst (which has alert.resolve). The break-glass admin
  // already exists from the seed; we register a credential for it
  // inside the break-glass test rather than in beforeAll because the
  // VA needs to live in the same browser context that drives the
  // sign-in + the later reauth ceremony.
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      const db = await openDB();
      try {
        await resetDB(db);
      } finally {
        await db.end();
      }
      await signInViaDex(page, "senior@qa.local");
      await page.request.delete("/api/session");
      const promoteDB = await openDB();
      try {
        await promote(promoteDB, "senior@qa.local", "senior_analyst");
      } finally {
        await promoteDB.end();
      }
    } finally {
      await ctx.close();
    }
  });

  test("OIDC reauth: modal → dex re-auth → operator re-click → resolved", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await signInViaDex(page, "senior@qa.local");

      // Seed a critical alert that the senior_analyst can resolve.
      // Has to land AFTER sign-in so the audit row from JIT lookup
      // doesn't pollute the assertion later.
      const seedDB = await openDB();
      let alertId: number;
      try {
        alertId = await seedCriticalAlert(seedDB, {
          hostId: TEST_HOST_ID,
          ruleId: `${TEST_RULE_ID}-oidc`,
          title: "OIDC reauth modal - critical alert",
        });
      } finally {
        await seedDB.end();
      }

      await page.goto("/ui/alerts");
      const oidcAlertRow = page.locator("tr", {
        hasText: "OIDC reauth modal - critical alert",
      });
      await expect(oidcAlertRow).toBeVisible({ timeout: 15_000 });

      // Age the session past DefaultReauthWindow (30 min). 1 hour
      // gives a 2x safety margin.
      const ageDB = await openDB();
      try {
        await ageDB.query(
          `UPDATE sessions
              SET last_auth_at = NOW(6) - INTERVAL 1 HOUR
            WHERE user_id = (SELECT id FROM users WHERE email = 'senior@qa.local')`,
        );
      } finally {
        await ageDB.end();
      }

      // Click Resolve scoped to the seeded row so a parallel test that
      // seeded its own alert into the same view (or an unrelated row
      // from earlier setup) can't intercept the click and flake this
      // spec. Chokepoint should fire reauth_required and the hook
      // should pop the modal.
      await oidcAlertRow.getByRole("button", { name: /^resolve$/i }).click();

      const dialog = page.locator("dialog.reauth-dialog");
      await expect(dialog).toBeVisible({ timeout: 10_000 });
      // OIDC flow shows the SSO button, not the password input.
      await expect(
        dialog.getByRole("button", { name: /continue with single sign-on/i }),
      ).toBeVisible();
      await expect(dialog.getByLabel(/password/i)).not.toBeVisible();

      // Click "Continue with single sign-on": full-page navigate to
      // /api/auth/login?reauth=1&next=/ui/alerts → dex → callback →
      // back to /ui/alerts with a fresh session.
      await Promise.all([
        page.waitForURL(/localhost:5556\/dex/, { timeout: 30_000 }),
        dialog
          .getByRole("button", { name: /continue with single sign-on/i })
          .click(),
      ]);

      // Dex with prompt=login re-asks for credentials even though
      // its own session cookie is intact.
      await page.locator('input[name="login"]').fill("senior@qa.local");
      await page.locator('input[name="password"]').fill(DEX_PASSWORD);
      await page.getByRole("button", { name: /login/i }).click();
      await page.waitForURL("**/ui/alerts", { timeout: 30_000 });

      // The OIDC reauth path does NOT auto-retry (page navigated away
      // mid-promise; React state is gone). Operator re-clicks Resolve:
      // chokepoint sees fresh last_auth_at, allows. Same row-scoped
      // locator pattern as the first click so the retry can't land on
      // the wrong row.
      await expect(oidcAlertRow).toBeVisible({ timeout: 15_000 });
      await oidcAlertRow.getByRole("button", { name: /^resolve$/i }).click();

      // Row vanishing is the operator-visible success signal
      // (AlertList's statusFilter="open" + applyStatus filters
      // resolved rows out of the in-memory list, see
      // ui/src/components/AlertList.tsx). The helper additionally
      // pins the DB state + the single authz.alert.resolve audit row.
      await expectAlertResolvedAndAudited(
        page,
        "OIDC reauth modal - critical alert",
        alertId,
      );
    } finally {
      await ctx.close();
    }
  });

  test("break-glass reauth: modal → password+WebAuthn → auto-retry → resolved", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    let va: VirtualAuthenticator | undefined;
    try {
      // VA must be installed BEFORE the redemption ceremony so the
      // credential it issues is signable by this same VA on the
      // later reauth WebAuthn challenge. The reauth modal runs
      // inline (no page navigation), so the same context's VA stays
      // in scope and the credential is reusable.
      va = await installVirtualAuthenticator(page);

      // Reset → mint token → walk redemption ceremony. Mirrors
      // tests/auth/break-glass-setup.spec.ts but inline so the VA +
      // page context stay scoped to this one test.
      const setupDB = await openDB();
      let alertId: number;
      try {
        await resetDB(setupDB);
        const plaintext = await mintBootstrapToken(setupDB);
        await page.goto(`/admin/break-glass/setup?token=${plaintext}`);
        await page.getByLabel(/password/i).fill(BG_PASSWORD);
        await page
          .getByRole("button", { name: /register security key/i })
          .click();
        // 30s (not the 15s used elsewhere): this navigation is gated on the
        // full WebAuthn registration ceremony (VA create() + server-side
        // credential persistence + session mint + redirect) which can exceed
        // 15s under CI load and flaked here once (the redirect lands a hair
        // late). Matches the OIDC navigation budgets above.
        await page.waitForURL(
          (url) =>
            !url.pathname.includes("break-glass") && !url.pathname.includes("login"),
          { timeout: 30_000 },
        );

        // The admin user lands signed-in with super_admin (per seed)
        // which grants alert.resolve. Seed a critical alert.
        alertId = await seedCriticalAlert(setupDB, {
          hostId: TEST_HOST_ID,
          ruleId: `${TEST_RULE_ID}-bg`,
          title: "break-glass reauth modal - critical alert",
        });
      } finally {
        await setupDB.end();
      }

      await page.goto("/ui/alerts");
      const breakglassAlertRow = page.locator("tr", {
        hasText: "break-glass reauth modal - critical alert",
      });
      await expect(breakglassAlertRow).toBeVisible({ timeout: 15_000 });

      // Age the break-glass session.
      const ageDB = await openDB();
      try {
        await ageDB.query(
          `UPDATE sessions
              SET last_auth_at = NOW(6) - INTERVAL 1 HOUR
            WHERE user_id = (SELECT id FROM users WHERE email = 'admin@fleet-edr.local')`,
        );
      } finally {
        await ageDB.end();
      }

      // First click scoped to the seeded row so a parallel test or
      // unrelated row can't intercept it. Modal opens.
      await breakglassAlertRow
        .getByRole("button", { name: /^resolve$/i })
        .click();
      const dialog = page.locator("dialog.reauth-dialog");
      await expect(dialog).toBeVisible({ timeout: 10_000 });
      // Break-glass flow shows the password input, not the SSO
      // button.
      await expect(dialog.getByLabel(/password/i)).toBeVisible();
      await expect(
        dialog.getByRole("button", { name: /continue with single sign-on/i }),
      ).not.toBeVisible();

      // Fill password + click confirm. VA signs the inline WebAuthn
      // challenge against the credential it minted at sign-in time.
      // The modal awaits both the per-IP rate, password verify, and
      // WebAuthn assertion; on success it resolves(true) which
      // triggers useReauthRetry to re-fire the original
      // updateAlertStatus call. NO page navigation here: the retry
      // happens inside the React tree.
      await dialog.getByLabel(/password/i).fill(BG_PASSWORD);
      await dialog
        .getByRole("button", { name: /confirm with security key/i })
        .click();

      // Modal closes after success, and useReauthRetry's awaited
      // retry fires updateAlertStatus AGAIN with a fresh session
      // (no page navigation; the retry happens inside the React
      // tree). The helper then asserts the row vanishes from the
      // open-status filter plus the DB + audit invariants.
      await expect(dialog).toBeHidden({ timeout: 15_000 });
      await expectAlertResolvedAndAudited(
        page,
        "break-glass reauth modal - critical alert",
        alertId,
      );
    } finally {
      if (va) await uninstallVirtualAuthenticator(va);
      await ctx.close();
    }
  });
});
