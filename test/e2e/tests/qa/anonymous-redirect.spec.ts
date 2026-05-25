import { test, expect } from "../../fixtures/test";
import { openDB, resetDB } from "../../fixtures/db";

// Anonymous-session probe at /ui/. The App.tsx top-level Routes mount AuthedApp under "*", which uses the session
// status to decide between the login page and the protected app. Verifying the redirect end-to-end (rather than
// just unit-testing AuthedApp) catches regressions where /api/auth/session returns 200 for an unauthenticated
// caller, a class of bug the spec calls out explicitly ("the UI SHALL probe the server's session endpoint on
// application load and SHALL render the login page when the probe indicates no active session").
test.describe("anonymous entry to the application", () => {
  test.beforeEach(async () => {
    const db = await openDB();
    try {
      // Reset the operator-side state so no leftover session from a sibling spec leaves a cookie that could
      // satisfy the probe. resetDB drops sessions; the browser context Playwright gives each test is fresh
      // anyway, but belt-and-braces here keeps the assertion robust if the harness ever stops isolating
      // contexts.
      await resetDB(db);
    } finally {
      await db.end();
    }
  });

  // spec:web-ui/authenticated-entry-to-the-application/anonymous-user-lands-on-the-login-page
  test("anonymous /ui/ lands on the login page with SSO and break-glass controls", async ({ page }) => {
    // No session cookie is set on a fresh browser context; the probe should 401 and the SPA should swap to
    // the login route. Wait on the URL containing /login rather than asserting the exact final pathname,
    // since the server may append a return-to query the spec does not pin.
    await page.goto("/ui/");
    await page.waitForURL((url) => url.pathname.includes("/login"), { timeout: 10_000 });

    // Phase 4c rebuilt the landing login page as SSO-only with a break-glass footer link (per
    // ui/src/components/Login.tsx). The pre-4c email+password form moved to /admin/break-glass. Asserting on
    // both controls catches a regression that drops either: SSO disappearing breaks every operator's normal
    // sign-in path; the break-glass link disappearing breaks the credential-recovery path that's the only way
    // back in when the IdP is down.
    await expect(page.getByRole("button", { name: /continue with single sign-on/i })).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByRole("link", { name: /break-glass/i })).toBeVisible();
  });
});
