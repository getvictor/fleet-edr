package detectionconfig_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// fakeAudit captures the audit events the service emits so the test can assert the action, target, actor, and reason.
type fakeAudit struct {
	events []identityapi.AuditEvent
}

func (f *fakeAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

func newService(t *testing.T, audit identityapi.AuditRecorder) *detectionconfig.Service {
	t.Helper()
	store, _ := openStore(t)
	svc := detectionconfig.NewService(store, nil, audit, nil)
	require.NoError(t, svc.Reload(t.Context()))
	return svc
}

func TestService_CreateExclusion_PersistsResolvesAndAudits(t *testing.T) {
	t.Parallel()
	audit := &fakeAudit{}
	svc := newService(t, audit)
	ctx := context.Background()
	actor := &identityapi.Actor{UserID: 42}

	excl, err := svc.CreateExclusion(ctx, actor, "Claude Code CLI", detectionconfig.CreateExclusionInput{
		RuleID:    "suspicious_exec",
		MatchType: api.ExclusionMatchParentPathGlob,
		Value:     "*/claude/versions/*",
	})
	require.NoError(t, err)
	require.NotZero(t, excl.ID)
	assert.Equal(t, "user:42", excl.CreatedBy, "store records the actor identifier as created_by")

	// The snapshot reloaded, so the resolver now suppresses the matching parent.
	assert.True(t, svc.Excluded("suspicious_exec", api.ExclusionMatchParentPathGlob,
		"/Users/d/.local/share/claude/versions/2/claude", "host-a"))

	// Listing returns it.
	list, err := svc.ListExclusions(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// Audit row carries the action, target, actor, and the reason in the payload.
	require.Len(t, audit.events, 1)
	ev := audit.events[0]
	assert.Equal(t, identityapi.AuditDetectionConfigExclusionCreate, ev.Action)
	assert.Equal(t, "detection_exclusion", ev.TargetType)
	require.NotNil(t, ev.UserID)
	assert.Equal(t, int64(42), *ev.UserID)
	assert.Equal(t, "Claude Code CLI", ev.Payload["reason"])
}

func TestService_UpsertRuleSetting_ResolvesAndAudits(t *testing.T) {
	t.Parallel()
	audit := &fakeAudit{}
	svc := newService(t, audit)
	ctx := context.Background()
	actor := &identityapi.Actor{UserID: 7}

	_, err := svc.UpsertRuleSetting(ctx, actor, "too noisy", detectionconfig.UpsertSettingInput{
		RuleID: "suspicious_exec", Mode: api.DetectionRuleModeDisabled,
	})
	require.NoError(t, err)

	mode, _ := svc.ResolveRuleMode("suspicious_exec", "host-a")
	assert.Equal(t, api.DetectionRuleModeDisabled, mode)

	settings, err := svc.ListRuleSettings(ctx)
	require.NoError(t, err)
	require.Len(t, settings, 1)

	require.Len(t, audit.events, 1)
	assert.Equal(t, identityapi.AuditDetectionConfigRuleSettingUpdate, audit.events[0].Action)
}

func TestService_DeleteExclusion(t *testing.T) {
	t.Parallel()
	audit := &fakeAudit{}
	svc := newService(t, audit)
	ctx := context.Background()
	actor := &identityapi.Actor{UserID: 1}

	excl, err := svc.CreateExclusion(ctx, actor, "r", detectionconfig.CreateExclusionInput{
		RuleID: "sudoers_tamper", MatchType: api.ExclusionMatchPathGlob, Value: "/usr/local/bin/munki",
	})
	require.NoError(t, err)

	require.NoError(t, svc.DeleteExclusion(ctx, actor, "resolved", excl.ID))
	assert.False(t, svc.Excluded("sudoers_tamper", api.ExclusionMatchPathGlob, "/usr/local/bin/munki", "host-a"),
		"snapshot reloaded after delete")

	require.ErrorIs(t, svc.DeleteExclusion(ctx, actor, "resolved", excl.ID), sql.ErrNoRows,
		"deleting a missing exclusion surfaces sql.ErrNoRows")

	// One create + one delete audited (the failed second delete short-circuits before audit).
	assert.Len(t, audit.events, 2)
}

func TestService_NilAuditDropsRowWithoutPanic(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil) // nil recorder
	ctx := context.Background()
	_, err := svc.CreateExclusion(ctx, &identityapi.Actor{UserID: 1}, "r", detectionconfig.CreateExclusionInput{
		RuleID: "dyld_insert", MatchType: api.ExclusionMatchSHA256, Value: "abc",
	})
	require.NoError(t, err, "a nil audit recorder must not fail the mutation")
}

func TestService_NewServicePanicsOnNilStore(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { detectionconfig.NewService(nil, nil, nil, nil) })
}
