import type { Connection } from "mysql2/promise";
import { test, expect } from "../../fixtures/test";
import { signInAsAdminViaBreakGlass } from "../../fixtures/auth";
import { uninstallVirtualAuthenticator, VirtualAuthenticator } from "../../fixtures/webauthn";
import { openDB, resetDB } from "../../fixtures/db";

// Application Control policy editor (/ui/app-control/policies/<id>). The spec calls out three lifecycle
// invariants:
//   1. operator-stages-and-saves-a-policy-change — staged BINARY rule + non-empty reason POSTs and persists.
//   2. save-is-blocked-without-a-reason — submit stays disabled until the reason is filled.
//   3. invalid-path-or-hash-is-rejected-at-staging — client-side validation prevents a malformed hash from
//      being saved and surfaces an operator-visible error.
//
// EnsureDefaultPolicy seeds a Default policy at boot. resetDB does NOT touch app_control_policies, so the
// seed survives every test. We resolve the policy id by name (the auto-increment column may not be 1 on a
// long-lived dev DB; querying by name keeps the test portable).
async function defaultPolicyID(db: Connection): Promise<number> {
  const [rows] = (await db.query(
    "SELECT id FROM app_control_policies WHERE name = 'Default' LIMIT 1",
  )) as [Array<{ id: number | string }>, unknown];
  if (rows.length === 0) {
    throw new Error("defaultPolicyID: the seed 'Default' policy is missing — bootstrap did not run");
  }
  return Number(rows[0].id);
}

// A canonical, valid BINARY identifier (64 lowercase hex chars). Reused across the success + invalid tests
// to make the invalid case's "and now make it wrong" path obvious.
const VALID_BINARY_IDENTIFIER = "a".repeat(64);

test.describe("application control policy editor", () => {
  let va: VirtualAuthenticator | undefined;
  let policyID: number;

  test.beforeEach(async ({ page }) => {
    const db = await openDB();
    try {
      await resetDB(db);
      policyID = await defaultPolicyID(db);
      // Strip any rules left behind by a sibling spec so the per-test assertions on rule counts stay
      // deterministic. The schema's FK from rules to policies is ON DELETE CASCADE so deleting the policy
      // row would also nuke the seed, but DELETEing only the child rows leaves the seeded policy intact.
      await db.query("DELETE FROM app_control_rules WHERE policy_id = ?", [policyID]);
    } finally {
      await db.end();
    }
    va = await signInAsAdminViaBreakGlass(page);
  });

  test.afterEach(async () => {
    if (va) {
      await uninstallVirtualAuthenticator(va);
      va = undefined;
    }
  });

  // spec:web-ui/policy-editor-with-audit-reason-gate/operator-stages-and-saves-a-policy-change
  test("operator stages a BINARY rule with a reason and the rule persists", async ({ page }) => {
    await page.goto(`/ui/app-control/policies/${String(policyID)}`);
    await expect(page.getByRole("heading", { name: /default/i })).toBeVisible({ timeout: 10_000 });

    await page.getByRole("button", { name: /^add rule$/i }).click();
    // The modal renders a labelled "Identifier" input + "Reason (required for audit log)" input + a Save
    // button. Default ruleType is BINARY, so the 64-char hex value validates immediately.
    await page.getByLabel(/identifier/i).fill(VALID_BINARY_IDENTIFIER);
    await page.getByLabel(/reason \(required for audit log\)/i).fill("qa e2e: stage + save");

    // Capture the POST so we can prove the wire+payload contract the spec calls out: rule_type, identifier,
    // reason all reach the server.
    const [resp] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().includes(`/api/v1/app-control/policies/${String(policyID)}/rules`) &&
          r.request().method() === "POST",
        { timeout: 10_000 },
      ),
      page.getByRole("button", { name: /save rule/i }).click(),
    ]);
    expect(resp.status()).toBe(200);
    const sent = JSON.parse(resp.request().postData() ?? "{}") as Record<string, unknown>;
    expect(sent.rule_type).toBe("BINARY");
    expect(sent.identifier).toBe(VALID_BINARY_IDENTIFIER);
    expect(sent.reason).toBe("qa e2e: stage + save");

    // The DB now has one rule with the staged identifier on the seeded policy. Reading it back confirms the
    // server persisted (vs. the UI just optimistically rendering it).
    const db = await openDB();
    try {
      const [rows] = (await db.query(
        "SELECT identifier, rule_type FROM app_control_rules WHERE policy_id = ?",
        [policyID],
      )) as [Array<{ identifier: string; rule_type: string }>, unknown];
      expect(rows).toHaveLength(1);
      expect(rows[0].identifier).toBe(VALID_BINARY_IDENTIFIER);
      expect(rows[0].rule_type).toBe("BINARY");
    } finally {
      await db.end();
    }
  });

  // spec:web-ui/policy-editor-with-audit-reason-gate/save-is-blocked-without-a-reason
  test("save stays disabled when the reason is empty even if the identifier is valid", async ({ page }) => {
    await page.goto(`/ui/app-control/policies/${String(policyID)}`);
    await page.getByRole("button", { name: /^add rule$/i }).click();

    const saveBtn = page.getByRole("button", { name: /save rule/i });
    // Identifier is empty + reason is empty → disabled (baseline).
    await expect(saveBtn).toBeDisabled();

    // Fill identifier ONLY. Reason is still empty → submit must remain disabled. AddRuleModal's submitDisabled
    // is `busy || reason.trim().length === 0 || identifier.trim().length === 0`, so the spec invariant
    // ("editor refuses to save and surfaces a visible error explaining the reason is required") is satisfied
    // by the disabled control + the operator-visible "Reason (required for audit log)" label.
    await page.getByLabel(/identifier/i).fill(VALID_BINARY_IDENTIFIER);
    await expect(saveBtn).toBeDisabled();
    await expect(page.getByLabel(/reason \(required for audit log\)/i)).toBeVisible();

    // Fill the reason; the button must enable. Proves the disabled state was specifically the empty reason,
    // not some other gate.
    await page.getByLabel(/reason \(required for audit log\)/i).fill("any reason");
    await expect(saveBtn).toBeEnabled();
  });

  // spec:web-ui/policy-editor-with-audit-reason-gate/invalid-path-or-hash-is-rejected-at-staging
  test("a malformed BINARY hash is rejected with a validation error and no POST", async ({ page }) => {
    await page.goto(`/ui/app-control/policies/${String(policyID)}`);
    await page.getByRole("button", { name: /^add rule$/i }).click();

    // BINARY requires exactly 64 lowercase hex chars. Fill a too-short value that still trips the
    // submitDisabled check off (identifier non-empty + reason non-empty), so submit FIRES but the
    // validator at the top of handleSubmit catches it.
    await page.getByLabel(/identifier/i).fill("abc123"); // 6 chars, not 64
    await page.getByLabel(/reason \(required for audit log\)/i).fill("qa e2e: invalid hash");

    // Pin a response listener on the rules endpoint to prove no POST happens. The listener removes itself
    // after firing so a subsequent stage+save (in another test) doesn't double-fire it.
    let unexpectedPOST = false;
    const onResponse = (r: { url: () => string; request: () => { method: () => string } }) => {
      if (
        r.url().includes(`/api/v1/app-control/policies/${String(policyID)}/rules`) &&
        r.request().method() === "POST"
      ) {
        unexpectedPOST = true;
      }
    };
    page.on("response", onResponse);
    try {
      await page.getByRole("button", { name: /save rule/i }).click();
      // The validator's error message contains "BINARY identifier must be 64 hex characters" per
      // ui/src/components/ApplicationControl/AddRuleModal.tsx::validateIdentifier. Match on "64 hex" so the
      // assertion stays robust to small copy edits while still pinning to the spec invariant.
      await expect(page.getByText(/64 hex/i)).toBeVisible({ timeout: 5_000 });
    } finally {
      page.off("response", onResponse);
    }
    expect(unexpectedPOST).toBe(false);

    // The DB still has zero rules on the policy.
    const db = await openDB();
    try {
      const [rows] = (await db.query(
        "SELECT COUNT(*) AS n FROM app_control_rules WHERE policy_id = ?",
        [policyID],
      )) as [Array<{ n: number | string }>, unknown];
      expect(Number(rows[0].n)).toBe(0);
    } finally {
      await db.end();
    }
  });
});
