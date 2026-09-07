import { test, expect } from "../../fixtures/test";

// The Mode row on rule detail (issue #813/#810), which reports the mode in force plus the sentences that explain and qualify it.
//
// The value carried a class from the day it was written and never got a style rule, so it rendered as plain text inside its own
// explanation and the row read as one run-on: "Monitor This rule records what it would have fired on and raises no alert. This is
// the mode the rule declares. Resolved at global scope; ...". Nothing below the browser could see it. The vitest suite asserts the
// row's TEXT, which was correct throughout, and jsdom applies no cascade worth measuring.
test.describe("rule detail mode row", () => {
  // spec:web-ui/detection-configuration-admin-views/the-rule-detail-view-reports-the-mode-a-rule-runs-in
  test("the mode value is distinguishable from the sentences explaining it", async ({ signedInAdmin: page }) => {
    // A vendored rule in monitor mode, which is the shape that renders the row: an alerting rule on its declared mode has
    // nothing to report and the row is omitted entirely.
    await page.goto("/ui/rules/proc_creation_macos_applescript");

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
