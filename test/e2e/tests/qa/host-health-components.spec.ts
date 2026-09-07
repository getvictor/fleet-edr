import { test, expect } from "../../fixtures/test";
import { openDB } from "../../fixtures/db";

// The per-provider health panel on the host header (issue #702), which reports each capture provider as its own component with a
// status badge, a message, and when it last changed.
//
// The four components rendered in two different shapes at the same width. The row was one wrapping flex line, so where the
// message landed depended on how long the component's NAME was: "DNS proxy" is short enough that its message fitted beside it,
// while the three longer names pushed theirs onto the next line. An incidental wrap, not a responsive one, and invisible to any
// layer that does not lay the panel out.
const HOST_ID = "e2e-health-shape-0000-4000-8000-000000000001";

// Seeded rather than found, so the test states its own precondition instead of depending on whatever the database happens to
// hold. The component set is chosen for the property under test: "DNS proxy" is the shortest label the UI knows and the security
// extension the longest, which is exactly the spread that made the wrap land differently per component.
const COMPONENTS = [
  { type: "endpoint_security_extension", status: "healthy", reason: "activated", message: "Security extension connected" },
  { type: "content_filter", status: "healthy", reason: "activated", message: "Content filter is capturing" },
  { type: "dns_proxy", status: "healthy", reason: "activated", message: "DNS proxy is capturing" },
];

test.describe("host health components", () => {
  test.beforeEach(async () => {
    const db = await openDB();
    try {
      const nowNs = Date.now() * 1_000_000;
      await db.query(
        `INSERT INTO hosts (host_id, event_count, last_seen_ns) VALUES (?, 0, ?)
         ON DUPLICATE KEY UPDATE last_seen_ns = VALUES(last_seen_ns)`,
        [HOST_ID, nowNs],
      );
      await db.query(
        `INSERT INTO host_health (host_id, overall_status, components, reported_at_ns) VALUES (?, 'healthy', ?, ?)
         ON DUPLICATE KEY UPDATE components = VALUES(components), reported_at_ns = VALUES(reported_at_ns)`,
        [HOST_ID, JSON.stringify(COMPONENTS.map((c) => ({ ...c, last_transition_ns: nowNs }))), nowNs],
      );
    } finally {
      await db.end();
    }
  });

  // Seeded rows are removed again. resetHostData would take the host with it, but only for a spec that calls it, and leaving a
  // host and a health report behind means the next reader of this database finds a fleet member nobody enrolled.
  test.afterEach(async () => {
    const db = await openDB();
    try {
      await db.query("DELETE FROM host_health WHERE host_id = ?", [HOST_ID]);
      await db.query("DELETE FROM hosts WHERE host_id = ?", [HOST_ID]);
    } finally {
      await db.end();
    }
  });

  // spec:web-ui/the-host-detail-surfaces-the-health-conditions/every-component-is-laid-out-the-same-way
  test("every component renders in the same shape", async ({ signedInAdminShared: page }) => {
    await page.goto(`/ui/hosts/${HOST_ID}`);
    await page.getByRole("button", { name: /^details$/i }).click();

    const items = page.locator(".host-header__health-item");
    await expect(items).toHaveCount(COMPONENTS.length);

    // Measured rather than asserted per component: the defect was that ONE component differed from its siblings, so the property
    // is agreement across all of them.
    const shapes = await items.evaluateAll((els) =>
      els
        .map((el) => {
          const badge = el.querySelector('[class*="badge"]');
          const name = el.querySelector(".host-header__health-component");
          const message = el.querySelector(".host-header__health-message");
          if (!badge || !name || !message) return null;
          // Vertical CENTRES, not box tops. The status badge is a padded pill and the name is bare text, aligned on their
          // baselines, so their box tops differ by several pixels while sitting on the same visual line.
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

    expect(shapes).toHaveLength(COMPONENTS.length);
    // The whole intended shape, not half of it. Asserting only "the message is not beside the name" also passes when every span
    // is stacked on its own line, which puts the status badge above the name it describes and is a different wrong layout.
    expect(shapes.filter((s) => !s.badgeWithName)).toEqual([]);
    expect(shapes.filter((s) => s.messageOnNameLine)).toEqual([]);
    expect([...new Set(shapes.map((s) => s.messageLeft))]).toHaveLength(1);
  });
});
