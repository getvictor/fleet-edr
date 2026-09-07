import type { Connection } from "mysql2/promise";
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
    return toSetting(rows[0]);
  } finally {
    await db.end();
  }
}

/** toSetting projects a settings row, or its absence, into the snapshot shape. Shared so the locked and unlocked reads agree. */
type SettingRow = { mode: string; severity_override: string | null; settings: string | null; updated_by: string };

function toSetting(row?: SettingRow): GlobalRuleSetting | null {
  if (!row) return null;
  return {
    mode: row.mode,
    severityOverride: row.severity_override,
    settings: row.settings === null ? null : JSON.stringify(row.settings),
    updatedBy: row.updated_by,
  };
}

/**
 * lastWritten records what each fixture write left in a rule's global row, so a restore can tell its own change apart from
 * somebody else's.
 *
 * Module state rather than a parameter because the alternative is asking every call site to describe what it just wrote, which is
 * a second copy of the same fact and the copy that goes stale. The suite runs one worker (playwright.config.ts sets workers: 1),
 * so there is one spec writing at a time and the map cannot interleave with itself.
 */
const lastWritten = new Map<string, GlobalRuleSetting | null>();

/**
 * restoreGlobalRuleSetting puts back the operator's row, unless somebody else has written it since.
 *
 * What is restored is every column an operator sets: mode, severity_override, settings and updated_by. NOT the row's identity or
 * history. The row is deleted and re-inserted, so it returns with a fresh auto-increment id and fresh timestamps, and this makes
 * no attempt to preserve them: nothing in the product keys off that id, and a test helper reinstating an auto-increment value
 * could collide with a row inserted meanwhile, which is a worse failure than the one it would prevent.
 *
 * The concurrency check is the other half. Between the snapshot and the restore this used to assume nothing else wrote the row, so
 * an operator editing the same rule in the UI while the suite ran had their change reverted at teardown. Now the restore first
 * reads what is there: if it is not what this fixture last wrote, the row belongs to somebody else and is left alone. Reverting
 * their edit is the bug; failing the run over it would be worse, since teardown is not the place to fail, so it warns instead.
 */
export async function restoreGlobalRuleSetting(ruleId: string, previous: GlobalRuleSetting | null): Promise<void> {
  const expected = lastWritten.get(ruleId);
  lastWritten.delete(ruleId);

  const db = await openDB();
  try {
    // One transaction, and the read takes the lock. Comparing on one connection and writing on another leaves the window this is
    // supposed to close: an operator's edit landing between the two would pass the comparison and then be overwritten. SELECT
    // FOR UPDATE holds the row, and for a rule with no row it holds the gap, so a concurrent INSERT waits rather than slipping in.
    await db.beginTransaction();
    if (expected !== undefined && !sameSetting(await readLocked(db, ruleId), expected)) {
      await db.rollback();
      console.warn(
        `restoreGlobalRuleSetting(${ruleId}): the row changed since this spec wrote it, so it was left as it stands rather than ` +
          `reverted. Something else is editing this rule's global setting while the suite runs.`,
      );
      return;
    }
    if (previous === null) {
      await db.query("DELETE FROM detection_rule_settings WHERE rule_id = ? AND host_group_id = 0", [ruleId]);
    } else {
      await db.query(
        `INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, severity_override, settings, updated_by)
         VALUES (?, 0, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE mode = VALUES(mode), severity_override = VALUES(severity_override),
                                 settings = VALUES(settings), updated_by = VALUES(updated_by)`,
        [ruleId, previous.mode, previous.severityOverride, previous.settings, previous.updatedBy],
      );
    }
    await db.query("UPDATE detection_config_meta SET version = version + 1 WHERE id = 1");
    await db.commit();
  } catch (err) {
    await db.rollback();
    throw err;
  } finally {
    await db.end();
  }
}

/** readLocked reads the row inside the caller's transaction, holding it (or its gap) against a concurrent write. */
async function readLocked(db: Connection, ruleId: string): Promise<GlobalRuleSetting | null> {
  const [rows] = (await db.query(
    `SELECT mode, severity_override, settings, updated_by FROM detection_rule_settings
      WHERE rule_id = ? AND host_group_id = 0 FOR UPDATE`,
    [ruleId],
  )) as [Array<{ mode: string; severity_override: string | null; settings: string | null; updated_by: string }>, unknown];
  return toSetting(rows[0]);
}

/** sameSetting compares two snapshots by the columns an operator sets, which is everything a restore writes. */
function sameSetting(a: GlobalRuleSetting | null, b: GlobalRuleSetting | null): boolean {
  if (a === null || b === null) return a === b;
  return a.mode === b.mode && a.severityOverride === b.severityOverride && a.settings === b.settings && a.updatedBy === b.updatedBy;
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
  await writeCleared(ruleId);
  lastWritten.set(ruleId, null);
}

/** writeCleared is the delete itself, without recording it, so a restore can put the absence back without arming the check. */
async function writeCleared(ruleId: string): Promise<void> {
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
  // Read back rather than assume: the insert leaves severity_override and settings at whatever the row already held on the
  // conflict path, so what this write LEFT is not what it asked for, and the restore compares against what is there.
  lastWritten.set(ruleId, await takeGlobalRuleSetting(ruleId));
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
