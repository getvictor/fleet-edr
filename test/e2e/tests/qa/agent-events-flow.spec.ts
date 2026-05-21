// L4 smoke test for the M5 Playwright agent fixture: drive each shared M3 scenario through fixtures/agent.ts and confirm the events
// land in the server's `events` table with the right host_id and event_type. This is the wire test - no UI navigation - because the
// fixture's primary contract is "scenario YAML -> /api/events" wire shape. UI specs that use the fixture (host list rendering,
// process tree, alert detail) build on the wire contract proven here; if this spec is red, the UI specs would also be red but with
// confusing DOM-level failures, so this one fails first.
//
// State management: each test mints a fresh UUID host_id via crypto.randomUUID() and passes it as hostIdOverride. This sidesteps
// the global DB reset that fixtures/db.ts uses for the auth specs - the `events` table has FK relationships (alert_events references
// it) that make a blanket DELETE awkward, and unique host_ids keep tests isolated from prior runs' rows just as effectively.
// Cleanup is therefore none: rows accumulate, but only with test-tagged host_ids that no production code path produces.

import * as crypto from "node:crypto";
import { test, expect } from "../../fixtures/agent";
import { openDB } from "../../fixtures/db";

const scenarios = [
  { file: "quiet-host.yaml", expectedEventTypes: ["snapshot_heartbeat"] },
  { file: "exec-fork-exit.yaml", expectedEventTypes: ["fork", "exec", "exit"] },
  { file: "dns-and-network.yaml", expectedEventTypes: ["dns_query", "network_connect"] },
];

test.describe("L4 agent fixture: scenarios land in events table", () => {
  for (const sc of scenarios) {
    test(`${sc.file}: events land at /api/events`, async ({ agent }) => {
      const hostId = crypto.randomUUID().toUpperCase();
      const result = await agent.runScenario(sc.file, { hostIdOverride: hostId });

      expect(result.hostId).toBe(hostId);
      expect(result.eventsPosted).toBeGreaterThan(0);
      expect(result.hostToken).not.toBe("");

      const db = await openDB();
      try {
        const [rows] = (await db.query(
          `SELECT event_type, COUNT(*) AS n
             FROM events
            WHERE host_id = ?
            GROUP BY event_type`,
          [hostId],
        )) as [Array<{ event_type: string; n: number | string }>, unknown];

        const seen = new Set(rows.map((r) => r.event_type));
        for (const want of sc.expectedEventTypes) {
          expect(seen.has(want), `event_type ${want} present for ${sc.file}`).toBe(true);
        }
      } finally {
        await db.end();
      }
    });
  }

  test("hostIdOverride wins over scenario host.id", async ({ agent }) => {
    // The fixture promises a per-call host_id override so a single test can vary host_id without editing YAML. This case proves
    // the override path actually changes which row the event lands under (vs. silently using the scenario's host.id).
    const overrideId = crypto.randomUUID().toUpperCase();
    const result = await agent.runScenario("quiet-host.yaml", { hostIdOverride: overrideId });
    expect(result.hostId).toBe(overrideId);

    const db = await openDB();
    try {
      const [rows] = (await db.query("SELECT host_id FROM events WHERE host_id = ?", [overrideId])) as [
        Array<{ host_id: string }>,
        unknown,
      ];
      expect(rows.length).toBeGreaterThan(0);
    } finally {
      await db.end();
    }
  });
});
