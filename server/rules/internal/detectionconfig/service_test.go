package detectionconfig_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

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

// TestService_RefreshLoop_ConvergesAcrossReplicas models two replicas (separate Service+Store on one MySQL). A mutation on replica A
// bumps the shared version counter but only reloads A's own snapshot; B must converge via its periodic RefreshLoop without a restart
// or a mutation of its own. sudoers_tamper matches the WRITER process path, so the exclusion is a staged-installer writer under
// `/var`; it is written in the bare form and checked against the `/private/var` form, exercising the macOS firmlink aliasing end-to-end.
// spec:server-detection-rules-engine/detection-configuration-converges-across-replicas/a-replica-adopts-a-configuration-change-made-on-another-replica
func TestService_RefreshLoop_ConvergesAcrossReplicas(t *testing.T) {
	t.Parallel()
	storeA, db := openStore(t)
	svcA := detectionconfig.NewService(storeA, nil, nil, nil)
	require.NoError(t, svcA.Reload(t.Context()))

	// Replica B: its own Service + Store over the same database, started from an empty (boot) snapshot.
	svcB := detectionconfig.NewService(detectionconfig.NewStore(db), nil, nil, nil)
	require.NoError(t, svcB.Reload(t.Context()))
	require.False(t, svcB.Excluded("sudoers_tamper", api.ExclusionMatchPathGlob, "/private/var/db/munki/installer", "host-a"),
		"baseline: B excludes nothing")

	// t.Context() is cancelled at test cleanup, which stops the refresh-loop goroutine; no manual cancel needed.
	go svcB.RefreshLoop(t.Context(), 20*time.Millisecond)

	// Replica A creates the exclusion. This bumps detection_config_meta.version; B never sees the mutation directly.
	_, err := svcA.CreateExclusion(
		t.Context(), &identityapi.Actor{UserID: 1}, "munki staged installer writes sudoers",
		detectionconfig.CreateExclusionInput{
			RuleID: "sudoers_tamper", MatchType: api.ExclusionMatchPathGlob, Value: "/var/db/munki/installer",
		})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return svcB.Excluded("sudoers_tamper", api.ExclusionMatchPathGlob, "/private/var/db/munki/installer", "host-a")
	}, 3*time.Second, 20*time.Millisecond, "replica B should converge to the exclusion created on replica A via its refresh loop")
}
