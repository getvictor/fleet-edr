import { test, expect } from "../../fixtures/test";
import { openDB } from "../../fixtures/db";

// The Mode row on rule detail (issue #813/#810), which reports the mode in force plus the sentences that explain and qualify it.
//
// The value carried a class from the day it was written and never got a style rule, so it rendered as plain text inside its own
// explanation and the row read as one run-on: "Monitor This rule records what it would have fired on and raises no alert. This is
// the mode the rule declares. Resolved at global scope; ...". Nothing below the browser could see it. The vitest suite asserts the
// row's TEXT, which was correct throughout, and jsdom applies no cascade worth measuring.
// A vendored rule, which the corpus registers in monitor mode (#764). The row only renders for a rule that does not alert, so the
// spec needs one in that state.
const RULE_ID = "proc_creation_macos_applescript";

test.describe("rule detail mode row", () => {
  // Any operator setting for this rule is cleared, which the signed-in fixture does not do: it resets auth and deliberately
  // leaves detection configuration alone. Without this the rule's resolved mode is whatever a previous run left behind, and a
  // leftover `alert` removes the row entirely, so the spec would fail on a correct page.
  //
  // The version bump is not bookkeeping. A running replica reloads its configuration snapshot only when that counter moves, so a
  // settings write without it is invisible to the server for the life of the process.
  test.beforeEach(async () => {
    const db = await openDB();
    try {
      await db.query("DELETE FROM detection_rule_settings WHERE rule_id = ?", [RULE_ID]);
      await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
    } finally {
      await db.end();
    }
  });

  // spec:web-ui/detection-configuration-admin-views/the-rule-detail-view-reports-the-mode-a-rule-runs-in
  test("the mode value is distinguishable from the sentences explaining it", async ({ signedInAdminShared: page }) => {
    await page.goto(`/ui/rules/${RULE_ID}`);

    const modeValue = page.locator(".rule-detail__mode");
    await expect(modeValue).toHaveText(/monitor/i);

    // The property that matters is the CONTRAST between the value and the prose after it, not any particular weight, so the two
    // are measured against each other. A restyle that changes both together keeps this passing; one that drops the value's
    // treatment does not.
    const weights = await modeValue.evaluate((el) => {
      const value = Number.parseInt(getComputedStyle(el).fontWeight, 10);
      const row = el.closest("td") ?? el.parentElement;
      const prose = Number.parseInt(getComputedStyle(row as Element).fontWeight, 10);
      return { value, prose };
    });
    expect(weights.value).toBeGreaterThan(weights.prose);
  });
});
