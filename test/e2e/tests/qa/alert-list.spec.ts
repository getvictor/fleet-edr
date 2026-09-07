import type { Connection } from "mysql2/promise";
import { test, expect } from "../../fixtures/test";
import { resetHostData, signInAsAdminViaBreakGlass } from "../../fixtures/auth";
import { uninstallVirtualAuthenticator, VirtualAuthenticator } from "../../fixtures/webauthn";
import { openDB, resetDB, seedCriticalAlert } from "../../fixtures/db";

// Alert list page (/ui/alerts). Four scenarios in one file because they share the same setup shape (sign in
// admin, seed two alerts, navigate). Splitting per-scenario would triple the per-test break-glass setup cost
// (each ceremony burns two tokens out of the global 5/min bucket; see fixtures/auth.ts for the rate context).
//
// The seedCriticalAlert helper creates one process + one alert. Calling it twice with different (ruleId, title)
// produces two alerts on the same host with distinct process ids, which satisfies the alerts table's unique
// key on (source, host_id, rule_id, process_id).
const HOST_ID = "qa-alert-list-host";

async function ackAlertInDB(db: Connection, alertId: number): Promise<void> {
  await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = ?", [alertId]);
}

test.describe("alert list filtering and lifecycle", () => {
  let va: VirtualAuthenticator | undefined;
  let openAlertId: number;
  let ackedAlertId: number;
  const openTitle = "qa-alert-list-open-alert";
  const ackedTitle = "qa-alert-list-acknowledged-alert";

  test.beforeEach(async ({ page }) => {
    const db = await openDB();
    try {
      await resetDB(db);
      // resetHostData as well as resetDB, because resetDB clears the auth tables only. Without it each test's two seeded alerts
      // survive into the next one, and the second test's row locator matches four rows rather than two: a strict-mode violation,
      // not a pass. The spec has never run in CI, so nothing caught that it was only ever green on its first test.
      await resetHostData(db);
      // Seed two alerts on the same host: one open (the default-status), one acknowledged. The acknowledged
      // alert is created with status='open' (the schema default), then mutated via SQL so the seeded alert
      // doesn't depend on the UI's lifecycle controls (which are themselves under test).
      openAlertId = await seedCriticalAlert(db, {
        hostId: HOST_ID,
        ruleId: "qa-alert-list-open-rule",
        title: openTitle,
      });
      ackedAlertId = await seedCriticalAlert(db, {
        hostId: HOST_ID,
        ruleId: "qa-alert-list-acked-rule",
        title: ackedTitle,
      });
      await ackAlertInDB(db, ackedAlertId);
    } finally {
      await db.end();
    }
    va = await signInAsAdminViaBreakGlass(page);
  });

  test.afterEach(async () => {
    if (va) {
      await uninstallVirtualAuthenticator(va);
      va = undefined;
    }
  });

  // spec:web-ui/alert-list-filtering-and-lifecycle-controls/default-view-shows-only-open-alerts
  test("default view shows only open alerts", async ({ page }) => {
    await page.goto("/ui/alerts");
    // No heading to anchor on: #622 removed the on-page title from the top-nav tab pages. The alert table is what this page is.
    await expect(page.getByRole("table")).toBeVisible({ timeout: 10_000 });

    // The open alert's title is visible; the acknowledged one is not. Match by row to be robust to title text
    // appearing in another cell (defence in depth: the acked title only ever appears in its own row, but the
    // row-anchored locator stays correct if anyone adds a "recent activity" panel later).
    const openRow = page.locator("tr", { hasText: openTitle });
    const ackedRow = page.locator("tr", { hasText: ackedTitle });
    await expect(openRow).toBeVisible({ timeout: 10_000 });
    await expect(ackedRow).toHaveCount(0);
  });

  // spec:web-ui/alert-list-filtering-and-lifecycle-controls/operator-changes-the-status-filter
  test("changing the status filter refreshes the visible rows", async ({ page }) => {
    await page.goto("/ui/alerts");
    await expect(page.locator("tr", { hasText: openTitle })).toBeVisible({ timeout: 10_000 });

    // Switch the dropdown to "acknowledged". The visible rows must invert.
    await page.locator("#status-filter").selectOption("acknowledged");
    await expect(page.locator("tr", { hasText: ackedTitle })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("tr", { hasText: openTitle })).toHaveCount(0);

    // Switch back to "all" (the empty-string value): both rows must reappear.
    await page.locator("#status-filter").selectOption("");
    await expect(page.locator("tr", { hasText: openTitle })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("tr", { hasText: ackedTitle })).toBeVisible();
  });

  // spec:web-ui/alert-list-filtering-and-lifecycle-controls/operator-acknowledges-an-open-alert
  test("operator acknowledges an open alert and the DB reflects the transition", async ({ page }) => {
    await page.goto("/ui/alerts");
    const openRow = page.locator("tr", { hasText: openTitle });
    await expect(openRow).toBeVisible({ timeout: 10_000 });

    // The default filter is "open", so the row should disappear from view after the transition. Click the
    // row-scoped "Acknowledge" button to avoid a cross-row click when the seeded set grows.
    await openRow.getByRole("button", { name: /^acknowledge$/i }).click();
    await expect(openRow).toHaveCount(0, { timeout: 10_000 });

    // The DB transition is what the spec actually pins ("the alert's status transitions to acknowledged").
    // Read it back to make sure the UI's optimistic update wasn't masking a server-side failure.
    const verifyDB = await openDB();
    try {
      const [rows] = (await verifyDB.query(
        "SELECT status FROM alerts WHERE id = ?",
        [openAlertId],
      )) as [Array<{ status: string }>, unknown];
      expect(rows[0].status).toBe("acknowledged");
    } finally {
      await verifyDB.end();
    }
  });

  // spec:web-ui/alert-pivots-to-the-host-process-tree/operator-pivots-from-an-alert-to-the-host-context
  test("operator pivots from an alert to the host's process tree at the alert time", async ({ page }) => {
    await page.goto("/ui/alerts");
    const row = page.locator("tr", { hasText: openTitle });
    await expect(row).toBeVisible({ timeout: 10_000 });

    // The alert title pivots to /alerts/<id>, which #622 added so investigating an alert keeps the top nav on Alerts; it renders
    // the same ProcessTreeView the host route does. This spec expected the older /hosts/<id>?alert=&process=&at= destination and
    // has not run in CI since, so the route change went unnoticed here. The host link is a separate control in its own column.
    await row.getByRole("link", { name: openTitle }).click();
    await page.waitForURL((url) => url.pathname === `/ui/alerts/${openAlertId}`, { timeout: 10_000 });

    // The receiving page must still identify the host, so an operator can confirm where the pivot landed them.
    await expect(page.getByText(HOST_ID)).toBeVisible({ timeout: 10_000 });
  });
});
