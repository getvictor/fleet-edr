import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { openDB } from "./db";

/**
 * clearGlobalRuleSetting removes the GLOBAL-scope operator setting for one rule and bumps the configuration version.
 *
 * Global scope only. A blanket delete on rule_id would also remove every host-group override for that rule, which a browser test
 * arranging its own precondition has no business doing: the surfaces under test resolve the global setting, and the group rows
 * belong to whatever else is using the database.
 *
 * The version bump is not bookkeeping. A replica reloads its configuration snapshot only when that counter moves, so a settings
 * write without it is invisible to the running server for the life of the process.
 */
export async function clearGlobalRuleSetting(ruleId: string): Promise<void> {
  const db = await openDB();
  try {
    await db.query("DELETE FROM detection_rule_settings WHERE rule_id = ? AND host_group_id = 0", [ruleId]);
    await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
  } finally {
    await db.end();
  }
}

/**
 * waitForRuleMode blocks until the server REPORTS the rule running in the given mode, which is a different event from the write
 * that caused it.
 *
 * Bumping the version signals the periodic refresh; it does not perform it. A page loaded in the gap between the write and the
 * refresh sees the previous snapshot, and a spec that navigates immediately can therefore fail against correct UI code. Polling
 * the surface the UI itself reads is what makes the precondition true rather than merely requested.
 */
export async function waitForRuleMode(page: Page, ruleId: string, mode: string): Promise<void> {
  await expect
    .poll(
      async () => {
        const res = await page.request.get("/api/rules");
        if (!res.ok()) return "";
        const body = (await res.json()) as { rules?: { id: string; mode?: string }[] };
        return body.rules?.find((r) => r.id === ruleId)?.mode ?? "";
      },
      { timeout: 20_000, message: `the rule ${ruleId} never reached mode ${mode} in the server's config snapshot` },
    )
    .toBe(mode);
}
