// The preserve-and-restore fixture is the one piece of test scaffolding that WRITES to shared operator state: detection rule
// settings survive resetDB by design, so against a long-lived dev database a spec arranging a precondition is editing rows an
// operator owns. #908 recorded two limits of it. This pins what it now guarantees, because a helper whose guarantee is only
// stated in a comment is one whose guarantee drifts.
//
// No sign-in and no page, so it costs nothing from the break-glass setup budget and can share any phase.

import { test, expect } from "@playwright/test";
import { openDB } from "../../fixtures/db";
import type { GlobalRuleSetting } from "../../fixtures/detection-config";
import {
  clearGlobalRuleSetting,
  restoreGlobalRuleSetting,
  setGlobalRuleMode,
  takeGlobalRuleSetting,
} from "../../fixtures/detection-config";

// A rule id no catalog rule uses, so the row this spec writes is its own and a failure cannot leave an operator's tuning behind.
const RULE_ID = "e2e_detection_config_fixture_probe";

async function seedOperatorRow(): Promise<void> {
  const db = await openDB();
  try {
    await db.query(
      `INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, severity_override, updated_by)
       VALUES (?, 0, 'alert', 'critical', 'a-real-operator')
       ON DUPLICATE KEY UPDATE mode = VALUES(mode), severity_override = VALUES(severity_override), updated_by = VALUES(updated_by)`,
      [RULE_ID],
    );
  } finally {
    await db.end();
  }
}

async function editFromElsewhere(mode: string): Promise<void> {
  const db = await openDB();
  try {
    await db.query(
      "UPDATE detection_rule_settings SET mode = ?, updated_by = 'someone-else' WHERE rule_id = ? AND host_group_id = 0",
      [mode, RULE_ID],
    );
  } finally {
    await db.end();
  }
}

async function dropProbeRow(): Promise<void> {
  const db = await openDB();
  try {
    await db.query("DELETE FROM detection_rule_settings WHERE rule_id = ?", [RULE_ID]);
  } finally {
    await db.end();
  }
}

test.describe("detection-config fixture preserves operator state", () => {
  test.beforeEach(dropProbeRow);
  test.afterEach(dropProbeRow);

  test("a cleared setting is restored on every column an operator sets", async () => {
    await seedOperatorRow();
    const previous = await takeGlobalRuleSetting(RULE_ID);
    expect(previous).not.toBeNull();

    await clearGlobalRuleSetting(RULE_ID);
    expect(await takeGlobalRuleSetting(RULE_ID)).toBeNull();

    await restoreGlobalRuleSetting(RULE_ID, previous);
    expect(await takeGlobalRuleSetting(RULE_ID)).toEqual(previous);
  });

  test("a row someone else changed is left as it stands rather than reverted", async () => {
    await seedOperatorRow();
    const previous = await takeGlobalRuleSetting(RULE_ID);

    await setGlobalRuleMode(RULE_ID, "monitor", "e2e-fixture-probe");
    // Stands in for an operator editing the same rule in the UI while the suite runs. Reverting this is the defect #908 records:
    // the restore would put its snapshot back over a change it never made.
    await editFromElsewhere("disabled");

    await restoreGlobalRuleSetting(RULE_ID, previous);

    const after = (await takeGlobalRuleSetting(RULE_ID)) as GlobalRuleSetting;
    expect(after.mode).toBe("disabled");
    expect(after.updatedBy).toBe("someone-else");
  });

  test("a rule with no setting is restored to having none", async () => {
    const previous = await takeGlobalRuleSetting(RULE_ID);
    expect(previous).toBeNull();

    await setGlobalRuleMode(RULE_ID, "alert", "e2e-fixture-probe");
    expect(await takeGlobalRuleSetting(RULE_ID)).not.toBeNull();

    await restoreGlobalRuleSetting(RULE_ID, previous);
    expect(await takeGlobalRuleSetting(RULE_ID)).toBeNull();
  });
});
