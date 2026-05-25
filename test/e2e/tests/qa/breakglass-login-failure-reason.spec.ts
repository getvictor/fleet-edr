import type { BrowserContext, Page } from "@playwright/test";
import { test, expect } from "../../fixtures/test";
import { openDB, resetDB, mintBootstrapToken } from "../../fixtures/db";
import {
  installVirtualAuthenticator,
  uninstallVirtualAuthenticator,
  VirtualAuthenticator,
} from "../../fixtures/webauthn";

// Break-glass login wrong-password path: the wire response collapses
// to a generic invalid_credentials (to resist user/credential
// enumeration), but the audit row carries the precise reason
// password.mismatch — so an operator scanning the audit log can tell
// a password failure apart from a missing-user / bad-assertion / no-
// credentials rejection. Sibling shape coverage at the Go layer is in
// server/identity/internal/breakglass/handler_test.go.
//
// Runs against the default dev server with no env overrides. The
// break-glass setup ceremony runs ONCE in beforeAll on a long-lived
// browser context; the wrong-password test reuses that same context
// so the virtual authenticator + its registered credential stay in
// scope (a fresh test context would have a new VA that doesn't know
// about the credential). One setup ceremony per file fits comfortably
// under DefaultSetupRatePerMin (5/min).

const RIGHT_PASSWORD = "qa-precise-reason-password";
const WRONG_PASSWORD = "definitely-not-the-password";

let setupCtx: BrowserContext | undefined;
let setupPage: Page;
let setupVA: VirtualAuthenticator | undefined;

test.describe.serial("break-glass login failure reason", () => {
  test.beforeAll(async ({ browser }) => {
    setupCtx = await browser.newContext();
    setupPage = await setupCtx.newPage();
    setupVA = await installVirtualAuthenticator(setupPage);
    const db = await openDB();
    try {
      await resetDB(db);
      const plaintext = await mintBootstrapToken(db);
      await setupPage.goto(`/admin/break-glass/setup?token=${plaintext}`);
      await setupPage.getByLabel(/password/i).fill(RIGHT_PASSWORD);
      await setupPage
        .getByRole("button", { name: /register security key/i })
        .click();
      await setupPage.waitForURL(
        (url) =>
          !url.pathname.includes("break-glass") && !url.pathname.includes("login"),
        { timeout: 15_000 },
      );
      await setupPage.request.delete("/api/session");
      // Clear audit rows from the setup so the wrong-password test's
      // assertion sees only its own failure row.
      await db.query("DELETE FROM audit_events");
    } finally {
      await db.end();
    }
  });

  test.afterAll(async () => {
    if (setupVA) await uninstallVirtualAuthenticator(setupVA);
    // Guard against beforeAll failing before setupCtx is set —
    // otherwise the afterAll throws and masks the original failure.
    if (setupCtx) await setupCtx.close();
  });

  // Wrong password + valid WebAuthn assertion. ValidateLogin passes
  // (the VA signs correctly with the registered credential); the
  // password check fails with ErrBadPassword; reasonForLoginErr maps
  // that to "password.mismatch". Wire shows the redacted
  // invalid_credentials; the audit row carries the precise reason.
  // spec:web-ui/authenticated-entry-to-the-application/failed-login-shows-a-non-enumerating-error
  test("wrong password collapses to invalid_credentials on the wire; audit carries password.mismatch", async () => {
    // setupPage retains the VA + registered credential from
    // beforeAll. Drive the wrong-password login here.
    await setupPage.goto("/ui/login");
    await setupPage.getByRole("link", { name: /break-glass/i }).click();
    await setupPage.getByLabel(/email/i).fill("admin@fleet-edr.local");
    await setupPage.getByLabel(/password/i).fill(WRONG_PASSWORD);

    // Capture the final /admin/break-glass POST status. The Playwright
    // Response handle returned by waitForResponse becomes unusable
    // once the page re-renders, so read status() synchronously inside
    // a one-shot response listener instead of holding the body.
    // page.once() removes itself after firing so subsequent tests in
    // this serial suite don't get spurious callbacks.
    let finalStatus: number | undefined;
    const onResponse = (r: { url: () => string; request: () => { method: () => string }; status: () => number }) => {
      if (
        r.url().endsWith("/admin/break-glass") &&
        r.request().method() === "POST"
      ) {
        finalStatus = r.status();
        setupPage.off("response", onResponse);
      }
    };
    setupPage.on("response", onResponse);

    await setupPage
      .getByRole("button", { name: /sign in with security key/i })
      .click();

    // The UI renders the redacted error text on a generic 401. Wait
    // for the operator-visible state, then assert status + audit.
    await expect(
      setupPage.getByText(/invalid email, password, or security key/i),
    ).toBeVisible({ timeout: 15_000 });
    expect(finalStatus).toBe(401);

    // Audit carries the precise reason.
    const auditDB = await openDB();
    try {
      const [rows] = (await auditDB.query(
        `SELECT JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reason')) AS reason
           FROM audit_events
          WHERE action = 'auth.breakglass.failure'
            AND actor_email = 'admin@fleet-edr.local'
          ORDER BY id DESC LIMIT 1`,
      )) as [Array<{ reason: string }>, unknown];
      expect(rows).toHaveLength(1);
      expect(rows[0].reason).toBe("password.mismatch");
    } finally {
      await auditDB.end();
    }
  });

  // The brute-force rate-limit case lives in
  // breakglass-challenge-rate-limit.spec.ts. Burning the per-IP rate
  // budget here would pollute the bucket for ~3 minutes and break any
  // subsequent break-glass-touching spec in the same default-env run.
});
