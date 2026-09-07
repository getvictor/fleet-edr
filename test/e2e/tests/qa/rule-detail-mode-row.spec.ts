import { test, expect } from "../../fixtures/test";
import type { GlobalRuleSetting } from "../../fixtures/detection-config";
import { clearGlobalRuleSetting, restoreGlobalRuleSetting, takeGlobalRuleSetting, waitForRuleMode } from "../../fixtures/detection-config";

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
  // The rule's GLOBAL setting is taken away for the duration and put back afterwards, rather than deleted.
  //
  // Cleared because the fixture resets auth and deliberately leaves detection configuration alone, so a leftover `alert` would
  // remove the row this spec is about and it would fail on a correct page. Restored because those rows are persistent shared
  // state: against a long-lived dev database, deleting one destroys an operator's actual tuning for good. oidc-jit-disabled
  // already preserves and restores the SSO flag for the same reason.
  // undefined means the snapshot never ran, which is NOT the same as running and finding no row. Sharing one
  // sentinel for both would make a failed setup delete an operator's setting on the way out.
  let previous: GlobalRuleSetting | null | undefined;

  test.beforeEach(async () => {
    previous = await takeGlobalRuleSetting(RULE_ID);
    await clearGlobalRuleSetting(RULE_ID);
  });

  test.afterEach(async () => {
    if (previous !== undefined) await restoreGlobalRuleSetting(RULE_ID, previous);
  });

  // spec:web-ui/detection-configuration-admin-views/the-rule-detail-view-reports-the-mode-a-rule-runs-in
  test("the mode value is distinguishable from the sentences explaining it", async ({ signedInAdminShared: page }) => {
    // The write above only signals the refresh; it does not perform it. Navigating straight away can load the previous snapshot,
    // in which a leftover setting still applies and the row is absent, so this waits for the server to report the mode first.
    await waitForRuleMode(page, RULE_ID, "monitor");
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
