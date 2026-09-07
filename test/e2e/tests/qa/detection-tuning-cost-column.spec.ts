import { test, expect } from "../../fixtures/test";

// The Cost column on the detection tuning table (issue #774), covered here because the two things that went wrong with it are
// both invisible to every layer below.
//
// The vitest suite asserts what the header SAYS and how the rows sort. It cannot assert how the header LOOKS, because jsdom does
// not apply a user-agent stylesheet, and the defect was entirely there: the header is a real <button> so the sort is focusable
// and announced, and Chrome's UA stylesheet sets text-transform and letter-spacing on form controls, which beats the inherited
// uppercase the sibling headers get. It shipped rendering "Cost (7d)" in title case beside RULE, OBSERVED (7D) and MODE, and no
// unit test could have seen it.
test.describe("detection tuning cost column", () => {
  // spec:observability-instrumentation/evaluation-statistics-are-readable-per-rule/the-ordering-control-still-reads-as-a-column-header
  test("the cost header renders as a header, not as a button", async ({ signedInAdmin: page }) => {
    await page.goto("/ui/detection-config");

    const headers = page.locator("table thead th");
    await expect(headers.filter({ hasText: /cost/i })).toHaveCount(1);

    // Compared against a SIBLING rather than against the literal "uppercase", so the test states the property that matters (this
    // header reads like the others) and keeps holding if the table's header styling is restyled wholesale.
    const sibling = await headers.filter({ hasText: /^MODE$/i }).evaluate((el) => {
      const s = getComputedStyle(el);
      return { textTransform: s.textTransform, letterSpacing: s.letterSpacing };
    });
    const cost = await headers
      .filter({ hasText: /cost/i })
      .locator("button")
      .evaluate((el) => {
        const s = getComputedStyle(el);
        return { textTransform: s.textTransform, letterSpacing: s.letterSpacing };
      });

    expect(cost).toEqual(sibling);
    expect(sibling.textTransform).not.toBe("none");
  });
});
