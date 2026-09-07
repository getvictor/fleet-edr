import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { openDB } from "./db";

/**
 * GlobalRuleSetting is a rule's global-scope row as it stood before a spec touched it, or null when there was none.
 *
 * Every column an operator can set, not just the mode: severity_override and settings carry their own tuning, and restoring a row
 * without them would hand back something that looks right and has lost the rest.
 */
export interface GlobalRuleSetting {
  mode: string;
  severityOverride: string | null;
  settings: string | null;
  updatedBy: string;
}

/**
 * takeGlobalRuleSetting reads a rule's global-scope row so a spec can put it back.
 *
 * resetDB deliberately leaves detection configuration alone, so these rows are persistent shared state: against a long-lived dev
 * database a spec that clears one to arrange a precondition destroys an operator's actual tuning, silently and for good. The
 * preserve-and-restore shape is the one oidc-jit-disabled already uses for the SSO flag, for the same reason.
 */
export async function takeGlobalRuleSetting(ruleId: string): Promise<GlobalRuleSetting | null> {
  const db = await openDB();
  try {
    const [rows] = (await db.query(
      "SELECT mode, severity_override, settings, updated_by FROM detection_rule_settings WHERE rule_id = ? AND host_group_id = 0",
      [ruleId],
    )) as [Array<{ mode: string; severity_override: string | null; settings: string | null; updated_by: string }>, unknown];
    const row = rows[0];
    if (!row) return null;
    return {
      mode: row.mode,
      severityOverride: row.severity_override,
      settings: row.settings === null ? null : JSON.stringify(row.settings),
      updatedBy: row.updated_by,
    };
  } finally {
    await db.end();
  }
}

/** restoreGlobalRuleSetting puts back exactly what takeGlobalRuleSetting found, including the absence of a row. */
export async function restoreGlobalRuleSetting(ruleId: string, previous: GlobalRuleSetting | null): Promise<void> {
  if (previous === null) {
    await clearGlobalRuleSetting(ruleId);
    return;
  }
  const db = await openDB();
  try {
    await db.query(
      `INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, severity_override, settings, updated_by)
       VALUES (?, 0, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE mode = VALUES(mode), severity_override = VALUES(severity_override),
                               settings = VALUES(settings), updated_by = VALUES(updated_by)`,
      [ruleId, previous.mode, previous.severityOverride, previous.settings, previous.updatedBy],
    );
    await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
  } finally {
    await db.end();
  }
}

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
 * setGlobalRuleMode writes the GLOBAL-scope operator setting for one rule and bumps the configuration version.
 *
 * The companion to clearGlobalRuleSetting, and scoped for the same reason: a spec arranging a precondition should touch the row
 * the surface under test resolves, not every host group's override of it.
 *
 * updated_by is written on the conflict path too. Updating only the mode, which is the shape this was extracted from, leaves a row
 * a previous run wrote still credited to that run's actor while carrying this one's mode, so anything reading the attribution sees
 * a pairing that never happened.
 */
export async function setGlobalRuleMode(ruleId: string, mode: string, updatedBy: string): Promise<void> {
  const db = await openDB();
  try {
    await db.query(
      `INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, updated_by)
       VALUES (?, 0, ?, ?)
       ON DUPLICATE KEY UPDATE mode = VALUES(mode), updated_by = VALUES(updated_by)`,
      [ruleId, mode, updatedBy],
    );
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
