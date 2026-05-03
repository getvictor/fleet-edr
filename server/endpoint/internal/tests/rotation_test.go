//go:build integration

package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/bootstrap"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// recordingAudit captures emitted AuditEvents so the integration tests
// can assert "the rotation produced exactly the audit row a SIEM
// reviewer will pivot from."
type recordingAudit struct {
	mu     sync.Mutex
	events []identityapi.AuditEvent
}

func (r *recordingAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) snapshot() []identityapi.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identityapi.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// withRotation builds the bootstrap.Deps overlay that wires
// HostTokenLifetime / Grace + the recording audit + command inserter
// for rotation tests. Returned helpers expose the captured commands +
// audit rows after each test action; the *sqlx.DB lets the test
// backdate host_token_issued_at to forge stale tokens.
func withRotation(t *testing.T, lifetime, grace time.Duration) (*bootstrap.Endpoint, *sqlx.DB, *recordingCommandInserter, *recordingAudit) {
	t.Helper()
	cmds := &recordingCommandInserter{}
	audit := &recordingAudit{}
	ep, db := newEndpointWithDB(t, func(d *bootstrap.Deps) {
		d.PolicyProvider = nil
		d.CommandInserter = cmds.Insert
		d.Audit = audit
		d.HostTokenLifetime = lifetime
		d.HostTokenGrace = grace
	})
	return ep, db, cmds, audit
}

// ageToken backdates host_token_issued_at via a direct UPDATE so the
// next VerifyToken sees the token as past lifetime without making the
// test wait. The same pattern is used in the unit-level rotation tests
// in endpoint/internal/service/rotation_test.go.
func ageToken(t *testing.T, db *sqlx.DB, hostID string, age time.Duration) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`UPDATE enrollments SET host_token_issued_at = ? WHERE host_id = ?`,
		time.Now().UTC().Add(-age), hostID)
	require.NoError(t, err)
}

// TestRotation_AutoTriggerOnStaleToken: enroll, age the token past
// lifetime, verify -> rotation auto-triggers. A rotate_token command
// queues with the new bearer in the payload; an audit row records
// trigger=auto. The new token verifies; the old token still verifies
// during grace and reports MatchedPrevious-equivalent behaviour by NOT
// triggering a second rotation.
func TestRotation_AutoTriggerOnStaleToken(t *testing.T) {
	ep, db, cmds, audit := withRotation(t, time.Hour, 5*time.Minute)
	ctx := t.Context()

	res, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h", OSVersion: "x", AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)
	oldToken := res.HostToken

	// Age past lifetime + first verify triggers rotation.
	ageToken(t, db, testHardwareUUID, 2*time.Hour)
	hostID, err := ep.Service().VerifyToken(ctx, oldToken)
	require.NoError(t, err)
	assert.Equal(t, testHardwareUUID, hostID)

	// Exactly one audit row + one rotate_token command emitted.
	events := audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, identityapi.AuditEnrollmentRotateToken, events[0].Action)
	assert.Equal(t, "auto", events[0].Payload["trigger"])
	assert.NotEmpty(t, events[0].Payload["previous_token_id_prefix"])

	calls := cmds.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "rotate_token", calls[0].CommandType)
	assert.Equal(t, testHardwareUUID, calls[0].HostID)
	assert.Contains(t, string(calls[0].Payload), "new_token")

	// The OLD token still verifies during grace AND must NOT trigger
	// another rotation -- the in-flight rotation is the source of truth.
	_, err = ep.Service().VerifyToken(ctx, oldToken)
	require.NoError(t, err)
	assert.Len(t, audit.snapshot(), 1, "grace verify must not emit another audit row")
	assert.Len(t, cmds.snapshot(), 1, "grace verify must not queue another rotate_token command")
}

// TestRotation_OldTokenRejectedAfterGrace: same setup, but a 100ms
// grace + sleep past it proves the previous-token grace boundary is
// the actual cutoff. Without this, a leaked token would stay valid
// forever even after rotation.
func TestRotation_OldTokenRejectedAfterGrace(t *testing.T) {
	ep, db, _, _ := withRotation(t, time.Hour, 100*time.Millisecond)
	ctx := t.Context()

	res, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h", OSVersion: "x", AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)
	oldToken := res.HostToken

	ageToken(t, db, testHardwareUUID, 2*time.Hour)
	_, err = ep.Service().VerifyToken(ctx, oldToken)
	require.NoError(t, err)

	// Sleep past the grace window and reverify with the old token.
	time.Sleep(300 * time.Millisecond)
	_, err = ep.Service().VerifyToken(ctx, oldToken)
	require.ErrorIs(t, err, api.ErrInvalidToken)
}

// TestRotation_OperatorPath: explicit Service.RotateToken bypasses the
// lifetime check (operator wants a fresh token NOW). Audit row carries
// trigger=operator + actor + reason. CommandID is non-zero so a UI
// can wait for the agent to ack via /api/commands/{id}.
func TestRotation_OperatorPath(t *testing.T) {
	ep, _, cmds, audit := withRotation(t, 24*time.Hour, 5*time.Minute)
	ctx := t.Context()

	_, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h", OSVersion: "x", AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)

	rot, err := ep.Service().RotateToken(ctx, testHardwareUUID,
		api.RotationTriggerOperator, "victor@example", "incident-2026-Q2")
	require.NoError(t, err)
	require.NotNil(t, rot.CommandID, "operator path must surface the queued command_id")
	assert.Positive(t, *rot.CommandID)
	assert.NotEmpty(t, rot.PreviousTokenIDPrefix)

	events := audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "operator", events[0].Payload["trigger"])
	assert.Equal(t, "victor@example", events[0].Payload["actor"])
	assert.Equal(t, "incident-2026-Q2", events[0].Payload["reason"])

	calls := cmds.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "rotate_token", calls[0].CommandType)
}

// TestRotation_RevokedHostNotRotatable: revoke + rotate must surface
// ErrNotFound rather than silently rehydrating the row. The audit
// reviewer's mental model is "revoke is terminal"; a back-door
// rotation would defeat that.
func TestRotation_RevokedHostNotRotatable(t *testing.T) {
	ep, _, cmds, audit := withRotation(t, 24*time.Hour, time.Minute)
	ctx := t.Context()

	_, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h", OSVersion: "x", AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)
	require.NoError(t, ep.Service().Revoke(ctx, testHardwareUUID, "compromised", "operator"))

	_, err = ep.Service().RotateToken(ctx, testHardwareUUID,
		api.RotationTriggerOperator, "operator", "test")
	require.ErrorIs(t, err, api.ErrNotFound)
	assert.Empty(t, audit.snapshot())
	assert.Empty(t, cmds.snapshot())
}
