// Shared helper for specs that need to enrol a host, post the process-tree-deep scenario, wait for the
// processor to materialise the rows, and navigate the operator to /ui/hosts/<id>. Two specs use this exact
// shape today: host-list-and-process-tree.spec.ts (the "process tree: process-tree-deep -> /ui/hosts/<id>
// renders the host page" test) and process-tree-detail.spec.ts (the three node-click + detail-panel + kill
// tests). Pulling the shape into a shared module collapses the cross-file duplication Sonar flags on the
// new-code path and keeps the per-test body focused on the interaction under test.

import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { openDB } from "./db";

// Minimal shape the helper consumes from the agent fixture. Importing the full AgentFixtures type would tug
// the whole fixture surface into this file; the helper only needs runScenario, and accepting the structural
// type keeps it usable from any spec that imports test from either fixtures/agent.ts or fixtures/test.ts.
export interface ProcessTreeAgent {
  runScenario(name: string, opts: { hostIdOverride: string }): Promise<{ hostId: string }>;
}

/**
 * setupProcessTreeDeep runs the process-tree-deep scenario against a freshly minted host id, waits until the
 * processor has materialised at least four process rows (the minimum the scenario produces - gating the
 * navigation on row count avoids a race where the tree page renders empty before processing catches up),
 * then navigates the supplied page to that host's /ui/hosts/<id> route and waits for at least one tree node
 * to be visible.
 *
 * Returns the host id so the caller can use it for cross-referencing DB rows (e.g. asserting a kill command
 * landed against the right host_id).
 */
export async function setupProcessTreeDeep(page: Page, agent: ProcessTreeAgent): Promise<string> {
  const hostId = crypto.randomUUID();
  const r = await agent.runScenario("process-tree-deep.yaml", { hostIdOverride: hostId });
  expect(r.hostId).toBe(hostId);

  const db = await openDB();
  try {
    await expect
      .poll(
        async () => {
          const [rows] = (await db.query(
            "SELECT COUNT(*) AS n FROM processes WHERE host_id = ?",
            [hostId],
          )) as [Array<{ n: number | string }>, unknown];
          return Number(rows[0].n);
        },
        { timeout: 10_000, message: "processor never materialised process rows for process-tree-deep" },
      )
      .toBeGreaterThanOrEqual(4);
  } finally {
    await db.end();
  }

  await page.goto(`/ui/hosts/${encodeURIComponent(hostId)}`);
  // Wait on the rendered tree: at least one g.node must exist before any node-click interaction can fire.
  await expect(page.locator("svg g.node").first()).toBeVisible({ timeout: 15_000 });
  return hostId;
}
