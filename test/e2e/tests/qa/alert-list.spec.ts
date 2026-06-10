import type { Connection } from "mysql2/promise";
import { test, expect } from "../../fixtures/test";
import { signInAsAdminViaBreakGlass } from "../../fixtures/auth";
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
    await expect(page.getByRole("heading", { name: /alerts/i })).toBeVisible({ timeout: 10_000 });

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

    // The alert title is the pivot link (per AlertList.tsx: it links to /hosts/<id>?alert=<id>&process=<pid>
    // &at=<ms>). Click it and verify the destination URL carries all three query params and lands on the
    // alerted host's process tree page.
    await row.getByRole("link", { name: openTitle }).click();
    await page.waitForURL(
      (url) =>
        url.pathname === `/ui/hosts/${HOST_ID}` &&
        url.searchParams.has("alert") &&
        url.searchParams.has("process") &&
        url.searchParams.has("at"),
      { timeout: 10_000 },
    );
    // The receiving page must render the host id somewhere so an operator can confirm where they are.
    // PageHeader renders host_id; matching on the page text is robust to layout tweaks.
    await expect(page.getByText(HOST_ID)).toBeVisible({ timeout: 10_000 });
  });
});
