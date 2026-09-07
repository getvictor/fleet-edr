import { test, expect } from "../../fixtures/test";

// The per-provider health panel on the host header (issue #702), which reports each capture provider as its own component with a
// status badge, a message, and when it last changed.
//
// The four components rendered in two different shapes at the same width. The row was one wrapping flex line, so where the
// message landed depended on how long the component's NAME was: "DNS proxy" is short enough that its message fitted beside it,
// while the three longer names pushed theirs onto the next line. An incidental wrap, not a responsive one, and invisible to any
// layer that does not lay the panel out.
test.describe("host health components", () => {
  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/every-component-is-laid-out-the-same-way
  test("every component renders in the same shape", async ({ signedInAdmin: page }) => {
    await page.goto("/ui/hosts");
    await page
      .getByRole("row")
      .filter({ hasText: /healthy/i })
      .first()
      .click();
    await page.getByRole("button", { name: /^details$/i }).click();

    const items = page.locator(".host-header__health-item");
    await expect(items.first()).toBeVisible();
    expect(await items.count()).toBeGreaterThan(1);

    // Measured rather than asserted per component: the defect was that ONE component differed from its siblings, so the property
    // is agreement across all of them. A message that shares its name's baseline is sitting beside the name instead of below it,
    // and messages that start at different x are in different shapes.
    const shapes = await items.evaluateAll((els) =>
      els
        .map((el) => {
          const badge = el.querySelector('[class*="badge"], [class*="pill"]');
          const name = el.querySelector(".host-header__health-component");
          const message = el.querySelector(".host-header__health-message");
          if (!badge || !name || !message) return null;
          // Vertical CENTRES, not box tops. The status badge is a padded pill and the name is bare text, and they are aligned on
          // their baselines, so their box tops differ by several pixels while sitting on the same visual line.
          const centre = (e: Element) => {
            const r = e.getBoundingClientRect();
            return r.top + r.height / 2;
          };
          const sameLine = (a: Element, b: Element) => Math.abs(centre(a) - centre(b)) < 6;
          return {
            badgeWithName: sameLine(badge, name),
            messageOnNameLine: sameLine(name, message),
            messageLeft: Math.round(message.getBoundingClientRect().left),
          };
        })
        .filter((s): s is { badgeWithName: boolean; messageOnNameLine: boolean; messageLeft: number } => s !== null),
    );

    expect(shapes.length).toBeGreaterThan(1);
    // The whole intended shape, not half of it. Asserting only "the message is not beside the name" also passes when every span
    // is stacked on its own line, which puts the status badge above the name it describes and is a different wrong layout.
    expect(shapes.filter((s) => !s.badgeWithName)).toEqual([]);
    expect(shapes.filter((s) => s.messageOnNameLine)).toEqual([]);
    expect([...new Set(shapes.map((s) => s.messageLeft))]).toHaveLength(1);
  });
});
