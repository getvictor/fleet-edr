import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../fixtures/test";

// The Value column of the detection tuning exclusion table (issue #1032), covered here because the defect is layout and jsdom does
// none: an exclusion value is usually a path or glob with no spaces, so it gave the browser nowhere to break and widened the whole
// table.
//
// The first fix capped the CELL with overflow-wrap: anywhere. That wrapped, and it was still wrong: a table cell ignores max-width in
// automatic layout, and anywhere drops the column's min-content width to one character, so the column was squeezed to a few
// characters and a 70-character glob ran over four lines while the table had room to spare. So the test pins both directions: the
// long value wraps, and it wraps AT the cap rather than well short of it.

// A real value from a live deployment, long enough to exceed the cap on any viewport.
const LONG_VALUE = "/Users/e2e/.local/share/mise/installs/lefthook/*/lefthook_*_MacOS_arm64";
const REASON = "e2e: detection-tuning-exclusion-value-wrap";

// 24rem at the root font size; the style under test states the cap in rem, so the test reads the root size rather than assuming 16px.
const CAP_REM = 24;

async function csrfToken(request: APIRequestContext): Promise<string> {
  const resp = await request.get("/api/session");
  expect(resp.status()).toBe(200);
  return ((await resp.json()) as { csrf_token: string }).csrf_token;
}

test.describe("detection tuning exclusion Value column", () => {
  // spec:web-ui/long-exclusion-values-wrap-within-a-capped-value-column/a-long-value-wraps-at-the-cap
  test("a long value wraps at the column cap instead of widening the table", async ({ signedInAdminShared: page }) => {
    const csrf = await csrfToken(page.request);
    const created = await page.request.post("/api/v1/detection-config/exclusions", {
      headers: { "X-Csrf-Token": csrf, "Content-Type": "application/json" },
      data: { rule_id: "suspicious_exec", match_type: "parent_path_glob", value: LONG_VALUE, reason: REASON },
    });
    expect(created.status()).toBe(201);
    const { id } = (await created.json()) as { id: number };

    try {
      await page.goto("/ui/detection-config");
      const value = page.locator("table td code", { hasText: LONG_VALUE });
      await expect(value).toBeVisible();

      const layout = await value.evaluate((code, capRem) => {
        const style = getComputedStyle(code);
        const rootFontSize = parseFloat(getComputedStyle(document.documentElement).fontSize);
        const lineHeight = Number.isNaN(parseFloat(style.lineHeight)) ? parseFloat(style.fontSize) * 1.2 : parseFloat(style.lineHeight);
        const box = code.getBoundingClientRect();
        const wrapper = code.closest("table")?.parentElement;
        return {
          width: box.width,
          lines: Math.round(box.height / lineHeight),
          cap: rootFontSize * capRem,
          tableScrollsHorizontally: wrapper ? wrapper.scrollWidth > wrapper.clientWidth : true,
        };
      }, CAP_REM);

      // At the cap, not short of it: the squeezed failure measured about half the cap.
      expect(layout.width).toBeGreaterThan(layout.cap - 2);
      expect(layout.width).toBeLessThanOrEqual(layout.cap + 1);
      expect(layout.lines).toBeGreaterThan(1);
      expect(layout.tableScrollsHorizontally).toBe(false);
    } finally {
      const deleted = await page.request.delete(`/api/v1/detection-config/exclusions/${String(id)}?reason=${encodeURIComponent(REASON)}`, {
        headers: { "X-Csrf-Token": csrf },
      });
      expect(deleted.status()).toBe(204);
    }
  });
});
