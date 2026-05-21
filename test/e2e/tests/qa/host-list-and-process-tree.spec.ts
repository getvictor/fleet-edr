// L4 (M6) — UI specs that drive the M5 agent fixture and assert on the host list + process tree pages. Four logically-distinct test
// cases consolidated into one .spec.ts FILE because each break-glass-setup ceremony burns 2 of the global 5/min token budget; four
// separate files would exhaust the bucket and the last specs would deadline-out on the setup challenge. A single file with
// test.describe.serial + a shared `page` lets us pay the 2-token ceremony once at beforeAll, then every test reuses the same
// authenticated context. Each test isolates its own DATA by calling resetHostData (which wipes events/processes/hosts but spares
// the sessions + webauthn_credentials rows that resetDB would nuke, killing the shared auth).
//
// Tests:
//   1. Empty state - signed-in admin with no hosts sees "No hosts reporting yet."
//   2. Many hosts  - 25 enrolments via enrollHostsBatch all render in <tr> rows
//   3. Event count - 3 hosts with different scenario lengths render the right Events column value
//   4. Process tree - process-tree-deep scenario produces a host page that renders
//
// Each test is independent post-resetHostData; the order in the describe block is alphabetical-by-purpose, not dependency.

import * as crypto from "node:crypto";
import { test, expect } from "../../fixtures/agent";
import { Page, Browser, BrowserContext } from "@playwright/test";
import { resetAndSignIn, resetHostData, uninstallVirtualAuthenticator } from "../../fixtures/auth";
import { openDB } from "../../fixtures/db";
import { VirtualAuthenticator } from "../../fixtures/webauthn";

test.describe.serial("L4 (M6): host list + process tree UI specs", () => {
  let ctx: BrowserContext;
  let page: Page;
  let va: VirtualAuthenticator;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    page = await ctx.newPage();
    va = await resetAndSignIn(page);
  });

  test.beforeEach(async () => {
    // resetHostData wipes only the agent-side tables (events/processes/hosts/enrollments + alert deps). Sessions + webauthn rows
    // survive, so the shared auth context stays valid across every test in this file.
    const db = await openDB();
    try {
      await resetHostData(db);
    } finally {
      await db.end();
    }
  });

  test.afterAll(async () => {
    await uninstallVirtualAuthenticator(va);
    await ctx.close();
  });

  test("empty state: signed-in admin with no hosts sees the empty-state copy", async () => {
    await page.goto("/ui/");
    // The HostList component renders an EmptyState with this exact text when hosts.length === 0. Asserting on the literal copy
    // means a future operator-visible copy edit surfaces here too.
    await expect(page.getByText("No hosts reporting yet.")).toBeVisible({ timeout: 10_000 });
    // Sanity: the hosts table is absent on the empty path.
    await expect(page.locator("table")).toHaveCount(0);
  });

  test("many hosts: enrol 25 hosts via enrollHostsBatch -> all render in <tr>", async ({ agent }) => {
    const BATCH_SIZE = 25;
    const hosts = await agent.enrollHostsBatch(BATCH_SIZE);
    expect(hosts).toHaveLength(BATCH_SIZE);

    await page.goto("/ui/");
    // Wait on row count rather than a specific selector so layout tweaks (e.g. row className changes) don't break the assertion.
    await expect
      .poll(() => page.locator("tbody tr").count(), { timeout: 10_000, message: "host list never reached expected row count" })
      .toBe(BATCH_SIZE);

    // Spot-check one enrolled host_id appears in a cell - proves we're rendering THESE rows, not a leftover from a prior run.
    await expect(page.getByRole("cell", { name: hosts[0].hostId, exact: true })).toBeVisible();
  });

  test("event count: hosts.event_count column shows the per-scenario timeline length", async ({ agent }) => {
    interface Driven {
      hostId: string;
      expected: number;
    }
    const cases = [
      { scenarioFile: "quiet-host.yaml", expected: 1 },
      { scenarioFile: "exec-fork-exit.yaml", expected: 3 },
      { scenarioFile: "dns-and-network.yaml", expected: 2 },
    ];
    const driven: Driven[] = await Promise.all(
      cases.map(async (c) => {
        const hostId = crypto.randomUUID();
        const r = await agent.runScenario(c.scenarioFile, { hostIdOverride: hostId });
        expect(r.eventsPosted).toBe(c.expected);
        return { hostId, expected: c.expected };
      }),
    );

    // Wait for the processor to roll events into hosts.event_count via DB direct query - skips UI render lag for the wait itself
    // so the per-row UI assertion below has a clear target.
    await expect
      .poll(
        async () => {
          const db = await openDB();
          try {
            const ids = driven.map((d) => d.hostId);
            const ph = ids.map(() => "?").join(",");
            const [rows] = (await db.query(
              `SELECT host_id, event_count FROM hosts WHERE host_id IN (${ph})`,
              ids,
            )) as [Array<{ host_id: string; event_count: number | string }>, unknown];
            return rows
              .map((r) => `${r.host_id}=${String(r.event_count)}`)
              .sort()
              .join(",");
          } finally {
            await db.end();
          }
        },
        { timeout: 10_000, message: "hosts.event_count never converged to expected per-scenario counts" },
      )
      .toBe(
        driven
          .map((d) => `${d.hostId}=${String(d.expected)}`)
          .sort()
          .join(","),
      );

    await page.goto("/ui/");
    for (const d of driven) {
      const row = page.locator("tr").filter({ has: page.getByText(d.hostId, { exact: true }) });
      await expect(row).toBeVisible({ timeout: 10_000 });
      // Events column is the 3rd <td> (0-indexed 2): Host ID | Status | Events | Last seen.
      await expect(row.locator("td").nth(2)).toHaveText(String(d.expected));
    }
  });

  test("process tree: process-tree-deep -> /ui/hosts/<id> renders the host page", async ({ agent }) => {
    const hostId = crypto.randomUUID();
    const r = await agent.runScenario("process-tree-deep.yaml", { hostIdOverride: hostId });
    expect(r.hostId).toBe(hostId);

    // Wait for the processor to materialise process rows (fork+exec -> processes table). process-tree-deep has 4 fork+exec pairs.
    await expect
      .poll(
        async () => {
          const db = await openDB();
          try {
            const [rows] = (await db.query(
              "SELECT COUNT(*) AS n FROM processes WHERE host_id = ?",
              [hostId],
            )) as [Array<{ n: number | string }>, unknown];
            return Number(rows[0].n);
          } finally {
            await db.end();
          }
        },
        { timeout: 10_000, message: "processor never materialised process rows for process-tree-deep" },
      )
      .toBeGreaterThanOrEqual(4);

    await page.goto(`/ui/hosts/${encodeURIComponent(hostId)}`);
    // PageHeader renders the host_id; asserting on the text avoids depending on D3 SVG selectors (those are layout-tuning-fragile).
    await expect(page.getByText(hostId)).toBeVisible({ timeout: 15_000 });
  });
});
