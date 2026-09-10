package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// blockedBinaryPath is the executable the demo's application-control block refers to. It matches the exec in
// corpus/app-control-blocked-app.yaml, which is the process the block event is built from, so the rule seeded here denies
// exactly the binary the alert says was denied.
const blockedBinaryPath = "/Applications/CoinMiner.app/Contents/MacOS/CoinMiner"

// seedAppControlRule gives the demo's application-control block a policy that would actually have produced it.
//
// The demo fabricates the block event, because the real decision is made on-device by the extension's AUTH_EXEC walker and no
// fake agent emits one. Fabricating the event alone left the Application control page showing a Default policy with zero rules
// beside an alert claiming a policy had blocked CoinMiner: the story had no middle, and an operator clicking through from the
// alert found nothing that explained it.
//
// Idempotent on (policy_id, rule_type, identifier), so a container restart re-runs the seeder harmlessly.
//
// The policy itself is created by the server at boot, not here, and this does NOT invent one when it is absent: a rule hung off
// a policy id nothing else knows about would recreate the same disconnect one level down. It logs and returns instead of
// failing, because the rule is a coherence nicety and aborting the whole seed over it would cost the operator the entire demo
// to fix a page they might not open.
func seedAppControlRule(ctx context.Context, db dbExecQuerier, logger *slog.Logger) error {
	var policyID int64
	switch err := db.QueryRowContext(ctx,
		`SELECT id FROM app_control_policies WHERE id = ?`, appControlPolicyID).Scan(&policyID); {
	case errors.Is(err, sql.ErrNoRows):
		logger.WarnContext(ctx, "no application-control policy to attach the demo block rule to; the alert will cite an empty policy",
			"policy_id", appControlPolicyID)
		return nil
	case err != nil:
		return fmt.Errorf("look up demo app-control policy %d: %w", appControlPolicyID, err)
	}
	// enforcement PROTECT because the block event reports an execution that was actually denied; DETECT would mean the binary
	// ran and was only recorded, which is not what the alert says happened.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO app_control_rules
			(policy_id, rule_type, identifier, action, enforcement, enabled, severity, source, source_ref, custom_msg)
		VALUES (?, ?, ?, 'BLOCK', 'PROTECT', 1, ?, 'admin', ?, ?)
		ON DUPLICATE KEY UPDATE
			custom_msg = VALUES(custom_msg),
			severity   = VALUES(severity),
			enabled    = VALUES(enabled)`,
		policyID, appControlRuleType, blockedBinaryPath, appControlSeverity, appControlRuleID, appControlMessage,
	); err != nil {
		return fmt.Errorf("seed demo app-control rule: %w", err)
	}
	return nil
}
