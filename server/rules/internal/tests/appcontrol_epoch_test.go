//go:build integration

package tests

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// spec:server-application-control/command-fan-out-on-policy-mutation/the-policy-epoch-advances-when-the-database-clock-steps-back
//
// TestAppControl_PolicyEpochAdvancesWhenTheClockStepsBack puts each policy's updated_at an hour ahead of the database clock, which is
// what a host holds after the clock steps back, and runs every kind of policy mutation. Hosts order snapshots by epoch first, so an
// epoch taken from the clock alone would go backwards here and the new snapshot would be refused.
func TestAppControl_PolicyEpochAdvancesWhenTheClockStepsBack(t *testing.T) { //nolint:tparallel // subtests share one policy row
	t.Parallel()
	db := full.Open(t)
	rules, err := rulesbootstrap.New(t.Context(), rulesbootstrap.Deps{DB: db, Logger: slog.Default(), AuthZ: allowAllAuthZ{}})
	require.NoError(t, err)
	require.NoError(t, rules.ApplySchema(t.Context()))
	store := rules.ApplicationControlStore()
	ctx := t.Context()

	policy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	seeded, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: policy.ID, RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("1", 64), Actor: "usr_1", Reason: "fixture",
	})
	require.NoError(t, err)
	toDelete, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: policy.ID, RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("2", 64), Actor: "usr_1", Reason: "fixture",
	})
	require.NoError(t, err)

	severity := api.SeverityRuleHigh
	description := "renamed after the clock stepped back"
	mutations := []struct {
		name   string
		mutate func(context.Context) error
	}{
		{"create rule", func(ctx context.Context) error {
			_, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID: policy.ID, RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("3", 64), Actor: "usr_1", Reason: "r",
			})
			return err
		}},
		{"update rule", func(ctx context.Context) error {
			_, err := store.UpdateRule(ctx, api.UpdateRuleRequest{RuleID: seeded.ID, Severity: &severity, Actor: "usr_1", Reason: "r"})
			return err
		}},
		{"delete rule", func(ctx context.Context) error {
			_, err := store.DeleteRule(ctx, api.DeleteRuleRequest{RuleID: toDelete.ID, Actor: "usr_1", Reason: "r"})
			return err
		}},
		{"bulk upsert", func(ctx context.Context) error {
			_, err := store.BulkUpsertRules(ctx, api.BulkUpsertRulesRequest{
				PolicyID: policy.ID, Actor: "usr_1", Reason: "r",
				Items: []api.BulkUpsertRuleItem{{RuleType: api.RuleTypeTeamID, Identifier: "EQHXZ8M8AV"}},
			})
			return err
		}},
		{"update policy", func(ctx context.Context) error {
			_, err := store.UpdatePolicy(ctx, api.UpdatePolicyRequest{PolicyID: policy.ID, Description: &description, Actor: "usr_1", Reason: "r"})
			return err
		}},
	}
	// Sequential subtests: every mutation moves the same policy row, and each starts by pushing it ahead of the clock again.
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) { //nolint:paralleltest // sequential on one policy row, see above
			ahead := policyUpdatedAtAheadOfClock(ctx, t, db, policy.ID)
			require.NoError(t, m.mutate(ctx))
			after, err := store.GetPolicyByID(ctx, policy.ID)
			require.NoError(t, err)
			assert.Truef(t, after.UpdatedAt.After(ahead), "the epoch must move past %s, got %s", ahead, after.UpdatedAt)
		})
	}
}

// policyUpdatedAtAheadOfClock sets the policy's updated_at an hour past the database clock and returns the stored value.
func policyUpdatedAtAheadOfClock(ctx context.Context, t *testing.T, db *sqlx.DB, policyID int64) time.Time {
	t.Helper()
	_, err := db.ExecContext(ctx, `UPDATE app_control_policies SET updated_at = NOW(6) + INTERVAL 1 HOUR WHERE id = ?`, policyID)
	require.NoError(t, err)
	var ahead time.Time
	require.NoError(t, db.GetContext(ctx, &ahead, `SELECT updated_at FROM app_control_policies WHERE id = ?`, policyID))
	return ahead
}
