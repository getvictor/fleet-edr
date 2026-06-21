package detectionconfig_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	rulesmigrations "github.com/fleetdm/edr/server/rules/migrations"
	"github.com/fleetdm/edr/server/testdb"
)

// openStore opens an isolated test DB, applies the rules migration corpus
// (which includes the detection-config tables), and returns a Store.
func openStore(t *testing.T) (*detectionconfig.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, runner.Up(t.Context(), db, rulesmigrations.FS, runner.Options{
		Context:   "rules",
		TableName: "rules_goose_db_version",
	}))
	return detectionconfig.NewStore(db), db
}

func TestStoreCreateExclusionBumpsVersionAndResolves(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)
	ctx := context.Background()

	v0, err := s.Version(ctx)
	require.NoError(t, err)

	_, err = s.CreateExclusion(ctx, detectionconfig.CreateExclusionInput{
		RuleID:      "suspicious_exec",
		MatchType:   api.ExclusionMatchParentPathGlob,
		Value:       "*/claude/versions/*",
		HostGroupID: api.GlobalScope,
		Reason:      "Claude Code CLI, version-stamped path",
		Actor:       "alice",
	})
	require.NoError(t, err)

	v1, err := s.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, v0+1, v1, "a mutation must bump the config version")

	snap, err := s.LoadSnapshot(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, v1, snap.Version())
	assert.True(t, snap.Excluded("suspicious_exec", api.ExclusionMatchParentPathGlob,
		"/Users/dev/.local/share/claude/versions/2.1.178/claude", "host-a"),
		"the version-stamped parent must be excluded by the glob")
	assert.False(t, snap.Excluded("suspicious_exec", api.ExclusionMatchParentPathGlob, "/usr/bin/python3", "host-a"))
}

func TestStoreUpsertRuleSettingResolves(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)
	ctx := context.Background()

	_, err := s.UpsertRuleSetting(ctx, detectionconfig.UpsertSettingInput{
		RuleID:      "suspicious_exec",
		HostGroupID: api.GlobalScope,
		Mode:        api.DetectionRuleModeDisabled,
		Actor:       "alice",
	})
	require.NoError(t, err)

	snap, err := s.LoadSnapshot(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, api.DetectionRuleModeDisabled, snap.Mode("suspicious_exec", "host-a"))

	// Upsert again on the same (rule, scope) flips the mode in place (no duplicate row).
	_, err = s.UpsertRuleSetting(ctx, detectionconfig.UpsertSettingInput{
		RuleID:           "suspicious_exec",
		HostGroupID:      api.GlobalScope,
		Mode:             api.DetectionRuleModeAlert,
		SeverityOverride: "critical",
		Actor:            "bob",
	})
	require.NoError(t, err)

	all, err := s.ListRuleSettings(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1, "upsert on the same (rule, scope) must not create a duplicate row")

	snap, err = s.LoadSnapshot(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, api.DetectionRuleModeAlert, snap.Mode("suspicious_exec", "host-a"))
	assert.Equal(t, "critical", snap.SeverityOverride("suspicious_exec", "host-a"))
}

func TestStoreDeleteExclusion(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)
	ctx := context.Background()

	created, err := s.CreateExclusion(ctx, detectionconfig.CreateExclusionInput{
		RuleID: "sudoers_tamper", MatchType: api.ExclusionMatchPathGlob,
		Value: "/usr/local/bin/munki", HostGroupID: api.GlobalScope, Actor: "alice",
	})
	require.NoError(t, err)

	require.NoError(t, s.DeleteExclusion(ctx, created.ID))

	snap, err := s.LoadSnapshot(ctx, nil, nil)
	require.NoError(t, err)
	assert.False(t, snap.Excluded("sudoers_tamper", api.ExclusionMatchPathGlob, "/usr/local/bin/munki", "host-a"))

	assert.ErrorIs(t, s.DeleteExclusion(ctx, created.ID), sql.ErrNoRows, "deleting a missing row returns sql.ErrNoRows")
}

func TestStoreRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)
	ctx := context.Background()

	_, err := s.CreateExclusion(ctx, detectionconfig.CreateExclusionInput{
		RuleID: "suspicious_exec", MatchType: "bogus", Value: "x", Actor: "alice",
	})
	require.ErrorIs(t, err, detectionconfig.ErrInvalidRequest, "invalid match type is rejected")

	_, err = s.UpsertRuleSetting(ctx, detectionconfig.UpsertSettingInput{
		RuleID: "suspicious_exec", Mode: "bogus", Actor: "alice",
	})
	require.ErrorIs(t, err, detectionconfig.ErrInvalidRequest, "invalid mode is rejected")
}
