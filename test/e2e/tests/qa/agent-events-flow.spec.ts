// L4 smoke test for the M5 Playwright agent fixture: drive each shared M3 scenario through fixtures/agent.ts and confirm the events
// land in the server's `events` table with the right host_id, event_type, AND event counts. This is the wire test - no UI navigation -
// because the fixture's primary contract is "scenario YAML -> /api/events" wire shape. UI specs that use the fixture (host list
// rendering, process tree, alert detail) build on the wire contract proven here; if this spec is red, the UI specs would also be red
// but with confusing DOM-level failures, so this one fails first.
//
// State management: each test mints a fresh canonical-lowercase UUID via crypto.randomUUID() and passes it as hostIdOverride.
// This sidesteps the global DB reset that fixtures/db.ts uses for the auth specs - the events table has FK relationships
// (alert_events references it) that make a blanket DELETE awkward, and unique host_ids keep tests isolated from prior runs' rows
// just as effectively. Production agents also use canonical UUIDs (IOPlatformUUID), so what marks these rows as test-only is
// the hostname (`playwright.lab.local`) + agent_version (`playwright-l4-agent-fixture`) set by the fixture during enrollment, not
// the host_id format.

import * as crypto from "node:crypto";
import { test, expect } from "../../fixtures/agent";
import { openDB } from "../../fixtures/db";

interface ScenarioCase {
  file: string;
  /** Map of event_type -> expected exact count for that type. The sum is the expected total envelope count, asserted separately. */
  expectedCounts: Record<string, number>;
}

const scenarios: ScenarioCase[] = [
  { file: "quiet-host.yaml", expectedCounts: { snapshot_heartbeat: 1 } },
  { file: "exec-fork-exit.yaml", expectedCounts: { fork: 1, exec: 1, exit: 1 } },
  { file: "dns-and-network.yaml", expectedCounts: { dns_query: 1, network_connect: 1 } },
];

test.describe("L4 agent fixture: scenarios land in events table", () => {
  for (const sc of scenarios) {
    test(`${sc.file}: events land at /api/events with exact counts`, async ({ agent }) => {
      const hostId = crypto.randomUUID();
      const result = await agent.runScenario(sc.file, { hostIdOverride: hostId });

      expect(result.hostId).toBe(hostId);
      const expectedTotal = Object.values(sc.expectedCounts).reduce((a, b) => a + b, 0);
      expect(result.eventsPosted).toBe(expectedTotal);
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

        // Exact-set assertion: the event_types in the DB must equal exactly what the scenario declared - no missing types and no
        // surprises (extra inserts would suggest the fixture leaked through to a wrong host, or the server's ingest accepted a
        // mistyped event_type).
        const dbTypes = rows.map((r) => r.event_type).sort((a, b) => a.localeCompare(b, "en"));
        expect(dbTypes).toEqual(Object.keys(sc.expectedCounts).sort((a, b) => a.localeCompare(b, "en")));

        // Exact-count per event_type: catches partial-ingest cases the presence-only check used to miss.
        for (const row of rows) {
          expect(Number(row.n), `count for ${row.event_type} in ${sc.file}`).toBe(sc.expectedCounts[row.event_type]);
        }
      } finally {
        await db.end();
      }
    });
  }

  test("hostIdOverride wins over scenario host.id", async ({ agent }) => {
    // The fixture promises a per-call host_id override so a single test can vary host_id without editing YAML. This case proves
    // the override path actually changes which row the event lands under (vs. silently using the scenario's host.id). Asserts
    // exact event count too: quiet-host.yaml has 1 snapshot_heartbeat, so any other count would mean either the override missed
    // some envelopes (some went to the scenario's hard-coded host.id) or the assertion is reading the wrong host_id's rows.
    const overrideId = crypto.randomUUID();
    const result = await agent.runScenario("quiet-host.yaml", { hostIdOverride: overrideId });
    expect(result.hostId).toBe(overrideId);
    expect(result.eventsPosted).toBe(1);

    const db = await openDB();
    try {
      const [rows] = (await db.query(
        "SELECT event_type, COUNT(*) AS n FROM events WHERE host_id = ? GROUP BY event_type",
        [overrideId],
      )) as [Array<{ event_type: string; n: number | string }>, unknown];
      expect(rows).toHaveLength(1);
      expect(rows[0].event_type).toBe("snapshot_heartbeat");
      expect(Number(rows[0].n)).toBe(1);
    } finally {
      await db.end();
    }
  });
});
