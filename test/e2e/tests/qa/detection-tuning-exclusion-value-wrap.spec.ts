import type { ResultSetHeader } from "mysql2/promise";
import { test, expect } from "../../fixtures/test";
import { openDB } from "../../fixtures/db";

// The Value column of the detection tuning exclusion table (issue #1032), covered here because the defect is layout and jsdom does
// none: an exclusion value is usually a path or glob with no spaces, so it gave the browser nowhere to break and widened the whole
// table.
//
// The first fix capped the CELL with overflow-wrap: anywhere. That wrapped, and it was still wrong: a table cell ignores max-width in
// automatic layout, and anywhere drops the column's min-content width to one character, so the column was squeezed to a few
// characters and a long glob ran over four lines while the table had room to spare. So the test pins both directions: the
// long value wraps, and it wraps AT the cap rather than well short of it.

// A real value from a live deployment, long enough to exceed the cap on any viewport.
const LONG_VALUE = "/Users/e2e/.local/share/mise/installs/lefthook/*/lefthook_*_MacOS_arm64";
const REASON = "e2e: detection-tuning-exclusion-value-wrap";

// 24rem at the root font size; the style under test states the cap in rem, so the test reads the root size rather than assuming 16px.
const CAP_REM = 24;

// The row is written straight to the database rather than through the API, so the shared signed-in page only navigates and asserts,
// which is the contract signedInAdminShared states. The exclusion list reads the table directly, so no config version bump is needed
// for the row to render. A leftover from an interrupted run is cleared first, because a second copy of the value would make the
// locator ambiguous. The delete matches every column the insert below sets, so the only row it can reach is an exact copy of this
// fixture, never a row an operator or another spec wrote on a long-lived dev database.
async function seedExclusion(): Promise<number> {
  const db = await openDB();
  try {
    await db.query(
      `DELETE FROM detection_exclusions
       WHERE rule_id = 'suspicious_exec' AND match_type = 'parent_path_glob' AND value = ? AND host_group_id = 0
         AND reason = ? AND enabled = 1 AND expires_at IS NULL AND created_by = 'sys'`,
      [LONG_VALUE, REASON],
    );
    const [result] = await db.query<ResultSetHeader>(
      `INSERT INTO detection_exclusions (rule_id, match_type, value, host_group_id, reason, enabled, created_by)
       VALUES ('suspicious_exec', 'parent_path_glob', ?, 0, ?, 1, 'sys')`,
      [LONG_VALUE, REASON],
    );
    return result.insertId;
  } finally {
    await db.end();
  }
}

async function dropExclusion(id: number): Promise<void> {
  const db = await openDB();
  try {
    await db.query("DELETE FROM detection_exclusions WHERE id = ?", [id]);
  } finally {
    await db.end();
  }
}

test.describe("detection tuning exclusion Value column", () => {
  // spec:web-ui/long-exclusion-values-wrap-within-a-capped-value-column/a-long-value-wraps-at-the-cap
  test("a long value wraps at the column cap instead of widening the table", async ({ signedInAdminShared: page }) => {
    const id = await seedExclusion();
    try {
      await page.goto("/ui/detection-config");
      const value = page.locator("table td code", { hasText: LONG_VALUE });
      await expect(value).toBeVisible();

      const layout = await value.evaluate((code, capRem) => {
        // Lines are counted as the text's line boxes, one client rect per line, rather than by dividing the box height by a
        // line-height. A computed line-height can be a unitless multiplier or "normal", and either turns that division into a
        // number that says nothing about wrapping.
        const range = document.createRange();
        range.selectNodeContents(code);
        const wrapper = code.closest("table")?.parentElement;
        return {
          width: code.getBoundingClientRect().width,
          lines: range.getClientRects().length,
          cap: Number.parseFloat(getComputedStyle(document.documentElement).fontSize) * capRem,
          tableScrollsHorizontally: wrapper ? wrapper.scrollWidth > wrapper.clientWidth : true,
        };
      }, CAP_REM);

      // At the cap, not short of it: the squeezed failure measured about half the cap.
      expect(layout.width).toBeGreaterThan(layout.cap - 2);
      expect(layout.width).toBeLessThanOrEqual(layout.cap + 1);
      expect(layout.lines).toBeGreaterThan(1);
      expect(layout.tableScrollsHorizontally).toBe(false);
    } finally {
      await dropExclusion(id);
    }
  });
});
