import { test, expect } from "../../fixtures/test";
import { signInAsAdminViaBreakGlass } from "../../fixtures/auth";
import { uninstallVirtualAuthenticator, VirtualAuthenticator } from "../../fixtures/webauthn";
import { openDB, resetDB } from "../../fixtures/db";

// ATT&CK coverage page. Renders the rule-to-technique mapping grouped by tactic, with technique ids that link
// to upstream MITRE pages and rule ids that link to /ui/rules/<id>. The page also exposes an "Export JSON"
// control that downloads the same data as a MITRE ATT&CK Navigator layer file.
//
// Both scenarios in this file share one signed-in admin (the page is read-only, so a single beforeAll-style
// fixture would work, but we use per-test beforeEach to keep the spec readable + avoid coupling tests
// through shared state).
test.describe("ATT&CK coverage page", () => {
  let va: VirtualAuthenticator | undefined;

  test.beforeEach(async ({ page }) => {
    const db = await openDB();
    try {
      await resetDB(db);
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

  // spec:web-ui/att-ck-coverage-page/coverage-page-renders-technique-groups
  test("coverage page groups techniques by tactic, with MITRE + rule doc links", async ({ page }) => {
    // Sanity-check the server has at least one covered technique. If the catalog is empty the assertions
    // below would pass against an empty page, which would be a misleading green.
    const layer = await page.request.get("/api/attack-coverage");
    expect(layer.status()).toBe(200);
    const layerJSON = (await layer.json()) as {
      techniques: Array<{ techniqueID: string }>;
    };
    expect(layerJSON.techniques.length).toBeGreaterThan(0);
    const sampleTechnique = layerJSON.techniques[0].techniqueID;

    await page.goto("/ui/coverage");
    await expect(page.getByRole("heading", { name: /att&ck coverage/i })).toBeVisible({ timeout: 10_000 });

    // Each tactic row is rendered with scope="rowgroup" inside its own <tbody>. The tactic strings come from
    // the canonical 14-tactic kill chain (TACTIC_ORDER in AttackCoverage.tsx); we assert at least one is on
    // the page rather than enumerating which, because the catalog can change which tactics are covered.
    const tacticRowGroups = page.locator("th[scope='rowgroup']");
    await expect.poll(() => tacticRowGroups.count(), { timeout: 10_000 }).toBeGreaterThan(0);

    // The sampled technique id should link to its upstream MITRE page (subtechniques use "T1234/001" path
    // form per AttackCoverage.tsx's replace(".", "/")). Anchor by the technique id text plus the attack.mitre.org
    // origin so a future copy edit can't accidentally match an unrelated row.
    const techniqueLink = page.locator(`a[href*="attack.mitre.org/techniques/"]`, { hasText: sampleTechnique });
    await expect(techniqueLink).toBeVisible();
    await expect(techniqueLink).toHaveAttribute("target", "_blank");

    // At least one in-app rule link points at /rules/<id>; this is the per-technique "Covered by" cell.
    const ruleLink = page.locator(`a[href^="/ui/rules/"]`).first();
    await expect(ruleLink).toBeVisible();
  });

  // spec:web-ui/att-ck-coverage-page/operator-exports-the-navigator-layer
  test("operator exports the Navigator layer JSON via the export control", async ({ page }) => {
    await page.goto("/ui/coverage");
    // Wait until the export button is enabled (it stays disabled while the layer loads).
    const exportBtn = page.getByRole("button", { name: /export json/i });
    await expect(exportBtn).toBeEnabled({ timeout: 10_000 });

    // The download is triggered by a Blob + anchor click in-page; Playwright's waitForEvent("download")
    // intercepts the synthesised anchor and exposes the suggestedFilename + the saved path. Asserting on
    // the filename and that the saved file parses as JSON catches both regressions: a missing/renamed file
    // (filename mismatch) and a malformed serialisation (parse failure).
    const [download] = await Promise.all([page.waitForEvent("download"), exportBtn.click()]);
    expect(download.suggestedFilename()).toBe("fleet-edr-attack-coverage.json");

    const fs = await import("node:fs/promises");
    const path = await download.path();
    const body = await fs.readFile(path, "utf-8");
    const parsed = JSON.parse(body) as { techniques: unknown[] };
    expect(Array.isArray(parsed.techniques)).toBe(true);
  });
});
