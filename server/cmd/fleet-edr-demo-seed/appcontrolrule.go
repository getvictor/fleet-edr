package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// seedAppControlRule gives the demo's application-control block a policy rule that would actually have produced it, and returns
// the wire rule id that block must cite.
//
// The demo fabricates the block event, because the real verdict is made on-device by the extension's AUTH_EXEC walker and no
// fake agent emits one. Fabricating it alone left the Application control page showing a Default policy with zero rules beside
// an alert claiming a policy had blocked CoinMiner: the story had no middle, and an operator who went looking for the rule
// behind the alert found an empty policy. This gives the two ends something to meet at; it does not make the alert title a
// link, which is a separate UI gap tracked in issue #975.
//
// Two things this has to get right, both of which an earlier attempt got wrong (issue #971):
//
//   - The rule's identity on the wire is derived from its row id by rulesapi.ApplicationControlRuleID, NOT from source_ref. A
//     block citing some other string does not correspond to the rule at all, however similar the two look in the database.
//   - Inserting a rule without bumping the owning policy's version breaks the contract CreateRule keeps in a transaction:
//     "version changes imply snapshot changes". A rule added under an unchanged version is invisible to the snapshot the
//     agent and extension receive. The seeder cannot call CreateRule (it lives under server/rules/internal/), so it does the
//     same two writes in one transaction here.
//
// A missing policy is a logged skip rather than a failure: the seeder cannot create the policy (the server owns it), and
// aborting the whole seed over a coherence nicety would cost the operator the entire demo.
func seedAppControlRule(ctx context.Context, db dbExecQuerier, logger *slog.Logger) (string, error) {
	identifier, err := blockedBinaryPath()
	if err != nil {
		return "", err
	}
	var policyID int64
	switch err := db.QueryRowContext(ctx,
		`SELECT id FROM app_control_policies WHERE id = ?`, appControlPolicyID).Scan(&policyID); {
	case errors.Is(err, sql.ErrNoRows):
		logger.WarnContext(ctx, "no application-control policy to attach the demo block rule to; the alert will cite an empty policy",
			"policy_id", appControlPolicyID)
		return "", nil
	case err != nil:
		return "", fmt.Errorf("look up demo app-control policy %d: %w", appControlPolicyID, err)
	}

	ruleID, err := upsertRuleAndBumpPolicy(ctx, db, policyID, identifier)
	if err != nil {
		return "", err
	}
	wireID := rulesapi.ApplicationControlRuleID(ruleID)
	logger.InfoContext(ctx, "seeded the demo application-control rule",
		"policy_id", policyID, "rule_id", ruleID, "wire_rule_id", wireID, "identifier", identifier)
	return wireID, nil
}

// upsertRuleAndBumpPolicy writes the rule and the policy's version together, and returns the rule's row id.
//
// One transaction, because a rule visible under an unchanged policy version is exactly the state CreateRule's own comment says
// must not be reachable through a partial failure. The version moves only when the rule row actually changed: MySQL reports 0
// affected rows for an upsert that set identical values, and bumping on every container restart would report a snapshot change
// that did not happen.
func upsertRuleAndBumpPolicy(ctx context.Context, db dbExecQuerier, policyID int64, identifier string) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin app-control rule tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	// enforcement PROTECT because the block event reports an execution that was actually denied; DETECT would mean the binary
	// ran and was only recorded, which is not what the alert says happened.
	res, err := tx.ExecContext(ctx, `
		INSERT INTO app_control_rules
			(policy_id, rule_type, identifier, action, enforcement, enabled, severity, source, source_ref, custom_msg)
		VALUES (?, ?, ?, 'BLOCK', 'PROTECT', 1, ?, 'admin', ?, ?)
		ON DUPLICATE KEY UPDATE
			custom_msg = VALUES(custom_msg),
			severity   = VALUES(severity),
			enabled    = VALUES(enabled)`,
		policyID, appControlRuleType, identifier, appControlSeverity, appControlSourceRef, appControlMessage)
	if err != nil {
		return 0, fmt.Errorf("upsert demo app-control rule: %w", err)
	}
	// A driver that cannot report the affected count leaves us unable to tell an insert from a no-op, and the safe reading is
	// that the snapshot changed: bumping a version nothing needed costs a redundant fan-out, while not bumping one that did
	// change hides the rule from every agent. Not an error path, because there is a correct answer without one.
	affected, err := res.RowsAffected()
	if err != nil || affected != 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE app_control_policies SET version = version + 1 WHERE id = ?`, policyID); err != nil {
			return 0, fmt.Errorf("bump demo app-control policy version: %w", err)
		}
	}

	// Read the id back rather than trusting LAST_INSERT_ID, which an upsert that took the UPDATE branch does not set to the
	// existing row. The unique key is what the upsert matched on, so this resolves the same row either way.
	var ruleID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM app_control_rules WHERE policy_id = ? AND rule_type = ? AND identifier = ?`,
		policyID, appControlRuleType, identifier).Scan(&ruleID); err != nil {
		return 0, fmt.Errorf("read back demo app-control rule id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit app-control rule tx: %w", err)
	}
	return ruleID, nil
}

// blockedBinaryPath returns the executable the demo's application-control block refers to, read from the same scenario the
// block event is built from.
//
// Not a constant. The block derives its identifier from this scenario at runtime, so a second copy of the path in the seeder
// would drift silently the moment the corpus is edited, leaving a rule that denies one binary beside an alert about another.
func blockedBinaryPath() (string, error) { return blockedBinaryPathIn(hostManifest) }

// blockedBinaryPathIn is blockedBinaryPath over a given manifest, so its two failure branches are reachable from a test. Both
// describe a real misconfiguration a corpus edit can produce (the app-control scenario removed, or its exec deleted), which is
// why they are errors rather than something to shrug at, and why they should not be untestable.
func blockedBinaryPathIn(manifest []demoHost) (string, error) {
	for _, host := range manifest {
		for _, atk := range host.Attacks {
			if atk.Kind != kindAppControl {
				continue
			}
			sc, err := loadAttackScenario(atk.File)
			if err != nil {
				return "", err
			}
			_, execPath, ok := firstExec(sc)
			if !ok {
				return "", fmt.Errorf("app-control scenario %s has no exec to take the blocked path from", atk.File)
			}
			return execPath, nil
		}
	}
	return "", errors.New("no application-control scenario in the host manifest")
}
