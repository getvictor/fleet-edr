import { test, expect } from "../../fixtures/test";
import { signInAsAdminViaBreakGlass } from "../../fixtures/auth";
import { uninstallVirtualAuthenticator, VirtualAuthenticator } from "../../fixtures/webauthn";
import { openDB, resetDB } from "../../fixtures/db";

// Per-rule documentation page reachable from the coverage page and from any UI surface that links a rule id.
// The page renders the rule's title, summary, severity, ATT&CK mapping, event types, description, and
// optional sections (config, false-positives, limitations). An unknown rule id MUST land on an empty state
// that links back to the coverage page, not produce a hard error or 404.
//
// The fixture rules come from the registered catalog at server/rules/internal/catalog/. To avoid coupling the
// test to a specific rule's text we fetch /api/rules first, pick the first entry the server reports, and
// assert against THAT entry's fields. The page only needs to render any registered rule's documentation;
// pinning to a specific rule's copy would make the test fragile when catalog content moves.
test.describe("per-rule documentation page", () => {
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

  // spec:web-ui/per-rule-documentation-page/rule-detail-renders-documented-fields
  test("rule detail renders title, summary, severity, ATT&CK techniques, event types, and description", async ({
    page,
  }) => {
    // Pick the first registered rule from the server's docs endpoint. The catalog has at least one entry in
    // every build (release-packaging gates ensure the rules table is non-empty), so we can rely on it.
    const docs = await page.request.get("/api/rules");
    expect(docs.status()).toBe(200);
    const body = (await docs.json()) as {
      rules: Array<{
        id: string;
        doc: { title: string; summary: string; severity: string; description?: string };
      }>;
    };
    expect(body.rules.length).toBeGreaterThan(0);
    const target = body.rules[0];

    await page.goto(`/ui/rules/${encodeURIComponent(target.id)}`);

    // Title + id render in the PageHeader.
    await expect(page.getByRole("heading", { name: target.doc.title })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`code.rule-detail__id:has-text("${target.id}")`)).toBeVisible();

    // Summary, severity, and the per-section headings always render for any registered rule. Severity case
    // varies (Badge renders lowercase) so match case-insensitively.
    await expect(page.getByText(target.doc.summary, { exact: false })).toBeVisible();
    await expect(page.getByRole("row", { name: new RegExp(String.raw`severity\s+${target.doc.severity}`, "i") }))
      .toBeVisible();
    await expect(page.getByRole("row", { name: /att&ck/i })).toBeVisible();
    await expect(page.getByRole("row", { name: /event types/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /description/i })).toBeVisible();
  });

  // spec:web-ui/per-rule-documentation-page/unknown-rule-id-renders-a-navigable-empty-state
  test("unknown rule id renders an empty state that links back to coverage", async ({ page }) => {
    // A made-up rule id the catalog has never registered. Reserves the qa- prefix so any future qa fixture
    // rule can't shadow this test.
    await page.goto("/ui/rules/qa-unknown-rule-id-not-in-catalog");

    // The page must NOT 404. The SPA stays at /ui/rules/<bad-id> and renders an empty state with a link to
    // the coverage page. The exact copy is "Unknown rule <code> ... Back to coverage" per RuleDetail.tsx;
    // a regex on the prefix tolerates copy edits while still pinning to "unknown" + "rule" + the bad id.
    await expect(page.getByText(/unknown rule/i)).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("code", { hasText: "qa-unknown-rule-id-not-in-catalog" })).toBeVisible();
    const backLink = page.getByRole("link", { name: /coverage/i });
    await expect(backLink).toBeVisible();
    await expect(backLink).toHaveAttribute("href", /\/coverage$/);
  });
});
