// Rule attribution reaches the alert view (issue #765).
//
// The vendored SigmaHQ corpus ships under the Detection Rule License, which requires the rule's author be credited wherever a match
// is displayed. Every layer below this is already covered: the engine stamps the credit onto the alert (Go integration test), the
// store round-trips it, and the components render it (vitest). What no other layer proves is the whole journey a licence auditor
// would actually walk, which is the one this spec drives: a vendored rule is promoted, a real agent event matches it, and the
// author's name appears on the resulting alert in the browser.
//
// The scenario fires a VENDORED rule specifically. A rule this project wrote would exercise the same plumbing while proving nothing
// about the obligation, since the obligation is owed to somebody else.

import * as crypto from "node:crypto";
import { test, expect } from "../../fixtures/agent";
import { signInAsAdminViaBreakGlass, uninstallVirtualAuthenticator } from "../../fixtures/auth";
import type { VirtualAuthenticator } from "../../fixtures/webauthn";
import { openDB, resetDB } from "../../fixtures/db";

// The upstream rule the osascript scenario matches, and the author its file credits. Pinned as literals because they are the
// artifact the licence is about: a rename upstream should surface here as a failing assertion, not as a silently changed credit.
const RULE_ID = "proc_creation_macos_applescript";
const UPSTREAM_AUTHOR = "SigmaHQ, by Alejandro Ortuno, oscd.community";

test.describe("alert attribution", () => {
  let va: VirtualAuthenticator | undefined;

  // Above the default 30s. The journey is deliberately the long one: enrol, post, ingest, build the graph, evaluate, then poll the
  // rendered page. The default leaves no headroom over the poll budget itself, so a slow-but-working run fails as a timeout.
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    const db = await openDB();
    try {
      await resetDB(db);
      // Promote the vendored rule out of monitor. Written directly rather than through the detection-config API because the
      // promotion is this test's PRECONDITION, not its subject: routing it through the UI would make an attribution failure
      // indistinguishable from a promotion failure.
      await db.query(
        `INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, updated_by)
         VALUES (?, 0, 'alert', 'e2e-alert-attribution')
         ON DUPLICATE KEY UPDATE mode = VALUES(mode)`,
        [RULE_ID],
      );
      // Bumping the version counter is not optional bookkeeping: it IS the cache-invalidation signal. A replica's refresh loop
      // polls this counter and reloads its config snapshot only when it moves, so a settings row written without it is invisible
      // to the running server forever, not merely until the next tick.
      await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
    } finally {
      await db.end();
    }
    va = await signInAsAdminViaBreakGlass(page);
  });

  test.afterEach(async () => {
    if (va) await uninstallVirtualAuthenticator(va);
    const db = await openDB();
    try {
      await db.query("DELETE FROM detection_rule_settings WHERE rule_id = ?", [RULE_ID]);
      // Same reason as the insert: without the bump the server keeps serving this rule as promoted after the test that promoted
      // it has finished, and a later spec inherits an alerting rule it never asked for.
      await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
    } finally {
      await db.end();
    }
  });

  // Both surfaces in one test, following this suite's convention: each break-glass ceremony burns two tokens out of a global
  // 5/min bucket, so a second sign-in in the same file times out the redemption rather than testing anything. One sign-in, one
  // scenario run, two assertions on the two surfaces that display the match.
  test("an alert from a vendored rule credits its upstream author on every surface that shows it", async ({ page, agent }) => {
    // The promotion is seeded straight into the table, which does NOT reload the server's config snapshot the way a write through
    // the REST surface does; the replica picks it up on its 5s refresh tick instead. Posting the scenario before that lands
    // evaluates the rule while it is still in monitor, and the alert is never raised. Wait for the precondition to actually be in
    // force rather than assuming the insert took effect.
    await waitForPromotion(page);

    const hostId = crypto.randomUUID();
    await agent.runScenario("osascript-oneliner.yaml", { hostIdOverride: hostId });
    const alertId = await waitForAlert(page, hostId);

    await page.goto("/ui/alerts");

    // The credit belongs to the row it describes, not merely to the page, so the assertion is scoped to this alert's own row: a
    // stray occurrence elsewhere must not be able to carry it. Scoped by the row's link to THIS alert id rather than by hostname,
    // which the Host column renders and which the scenario shares with every other run. toBeVisible auto-waits for the
    // client-side fetch to render, and is used over toBeInTheDocument deliberately, since a credit rendered into a hidden node
    // satisfies a DOM query and not the licence.
    const row = page.locator("tr").filter({ has: page.locator(`a[href="/ui/alerts/${String(alertId)}"]`) });
    await expect(row.getByText(UPSTREAM_AUTHOR)).toBeVisible();

    // The breadcrumb is the alert's detail surface, so it displays a match and owes the same credit as the list.
    await page.goto(`/ui/alerts/${String(alertId)}`);
    await expect(page.locator(".alert-breadcrumb__origin")).toHaveText(UPSTREAM_AUTHOR);
  });
});

/**
 * waitForAlert polls the API until the promoted rule has raised an alert for this host, and returns its id.
 *
 * Deliberately NOT a poll over the rendered page. Ingestion, graph building and rule evaluation are all asynchronous behind the
 * ingest 200, so something has to wait for them; doing that by reloading the page in a loop conflates "the backend has produced
 * the alert yet" with "the UI displays its credit", and the first failing then reads as the second. It also does not work: reload
 * resolves on the load event, before the client-side fetch has repainted the table, so the count is taken against an empty page
 * every time. Waiting here leaves the UI assertions to Playwright's own auto-waiting, which does handle that.
 */
async function waitForAlert(page: import("@playwright/test").Page, hostId: string): Promise<number> {
  let alertId = 0;
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/api/alerts?host_id=${hostId}`);
        if (!res.ok()) return 0;
        const body: unknown = await res.json();
        const rows = (Array.isArray(body) ? body : []) as { id: number; rule_id: string }[];
        const hit = rows.find((a) => a.rule_id === RULE_ID);
        if (hit) alertId = hit.id;
        return hit ? 1 : 0;
      },
      { timeout: 30_000, message: "the promoted vendored rule never raised an alert for the scenario host" },
    )
    .toBe(1);
  return alertId;
}

/** waitForPromotion blocks until the server reports the vendored rule as actually running in alert mode. */
async function waitForPromotion(page: import("@playwright/test").Page): Promise<void> {
  await expect
    .poll(
      async () => {
        const res = await page.request.get("/api/rules");
        if (!res.ok()) return "";
        const body = (await res.json()) as { rules?: { id: string; mode?: string }[] };
        return body.rules?.find((r) => r.id === RULE_ID)?.mode ?? "";
      },
      { timeout: 20_000, message: "the seeded promotion never reached the server's config snapshot" },
    )
    .toBe("alert");
}
