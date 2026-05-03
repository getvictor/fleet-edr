package service_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/service"
	"github.com/fleetdm/edr/server/endpoint/testkit"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/testdb"
)

const (
	testHostID = "93DFC6F5-763D-5075-B305-8AC145D12F96"
	testSecret = "test-enroll-secret"
)

// fakeRecorder captures audit events for assertion. Must be safe to
// invoke from any goroutine; the verify-time auto-rotate path is
// synchronous today but a future scheduler may run it concurrently.
type fakeRecorder struct {
	events []identityapi.AuditEvent
}

func (f *fakeRecorder) Record(_ context.Context, e identityapi.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

// commandCapture records (host_id, command_type, payload) tuples so
// tests can assert which commands the service queued. Returns a fake
// command_id sequence (1, 2, ...) so the operator path can verify the
// CommandID field of the api.RotateResult.
type commandCapture struct {
	calls atomic.Int64
	last  struct {
		hostID      string
		commandType string
		payload     []byte
	}
}

func (c *commandCapture) Insert(_ context.Context, hostID, commandType string, payload []byte) (int64, error) {
	id := c.calls.Add(1)
	c.last.hostID = hostID
	c.last.commandType = commandType
	c.last.payload = payload
	return id, nil
}

// newServiceForTest stands up an endpoint Service backed by a real
// MySQL test DB, with a captured CommandInserter + audit recorder so
// each test can inspect the side effects of rotation.
func newServiceForTest(t *testing.T, lifetime, grace time.Duration) (svc api.Service, store *mysql.Store, db *sqlx.DB, audit *fakeRecorder, cmds *commandCapture) {
	t.Helper()
	db = testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store = mysql.NewStore(db)
	audit = &fakeRecorder{}
	cmds = &commandCapture{}
	svc = service.New(service.Options{
		Store:    store,
		Secret:   testSecret,
		Audit:    audit,
		Commands: cmds.Insert,
		Policy:   nil, // not exercised in these tests; paired-nil with Commands is OK because the enroll fan-out is the only consumer of the pair.
		Lifetime: lifetime,
		Grace:    grace,
		Logger:   slog.Default(),
	})
	return svc, store, db, audit, cmds
}

// enrollOne issues a fresh enrollment via the public Service.Enroll
// path and returns the bearer token + the row's current host_token_id
// (lifted out of the DB for tests that need to assert "this rotation
// changed the underlying id").
func enrollOne(t *testing.T, svc api.Service, hostID string) string {
	t.Helper()
	res, err := svc.Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: testSecret,
		HardwareUUID: hostID,
		Hostname:     "qa",
		AgentVersion: "v",
		OSVersion:    "o",
	}, "127.0.0.1")
	require.NoError(t, err)
	return res.HostToken
}

// ageToken backdates the host's host_token_issued_at by the given
// duration so the next VerifyToken sees the token as past lifetime
// without making the test wait. The schema column is NOT NULL with a
// CURRENT_TIMESTAMP default; a direct UPDATE is the cheap test-only
// way to forge token age.
func ageToken(t *testing.T, db *sqlx.DB, hostID string, age time.Duration) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`UPDATE enrollments SET host_token_issued_at = ? WHERE host_id = ?`,
		time.Now().UTC().Add(-age), hostID)
	require.NoError(t, err)
}

// A fresh token does not trigger rotation: the agent's normal poll
// shouldn't pay an extra UPDATE + INSERT + audit cost on every request.
func TestVerifyToken_FreshTokenDoesNotRotate(t *testing.T) {
	svc, _, _, audit, cmds := newServiceForTest(t, time.Hour, time.Minute)
	tok := enrollOne(t, svc, testHostID)

	hostID, err := svc.VerifyToken(t.Context(), tok)
	require.NoError(t, err)
	assert.Equal(t, testHostID, hostID)
	assert.Empty(t, audit.events, "fresh token must not emit any audit row")
	assert.Zero(t, cmds.calls.Load(), "fresh token must not queue any rotate_token command")
}

// A token past lifetime triggers rotation on the next verify, queues a
// rotate_token command for the agent, and emits exactly one audit row
// tagged with trigger=auto.
func TestVerifyToken_StaleTokenAutoRotates(t *testing.T) {
	svc, _, db, audit, cmds := newServiceForTest(t, time.Hour, time.Minute)
	tok := enrollOne(t, svc, testHostID)
	ageToken(t, db, testHostID, 2*time.Hour) // well past 1h lifetime

	hostID, err := svc.VerifyToken(t.Context(), tok)
	require.NoError(t, err)
	assert.Equal(t, testHostID, hostID)

	require.Len(t, audit.events, 1, "stale-token verify must emit exactly one audit row")
	got := audit.events[0]
	assert.Equal(t, identityapi.AuditEnrollmentTokenRotated, got.Action)
	assert.Equal(t, "host", got.TargetType)
	assert.Equal(t, testHostID, got.TargetID)
	assert.Equal(t, "auto", got.Payload["trigger"])
	assert.NotEmpty(t, got.Payload["previous_token_id_prefix"])

	assert.Equal(t, int64(1), cmds.calls.Load(), "exactly one rotate_token command must be queued")
	assert.Equal(t, testHostID, cmds.last.hostID)
	assert.Equal(t, "rotate_token", cmds.last.commandType)
	assert.Contains(t, string(cmds.last.payload), "new_token", "rotate_token payload must carry the new bearer")
}

// A verify against the previous-token grace path must NOT trigger a
// rotation: rotation is already in flight (the new token has been
// issued; the agent just hasn't picked it up yet). Triggering another
// would discard the in-flight rotation prematurely.
func TestVerifyToken_GraceTokenDoesNotReRotate(t *testing.T) {
	svc, _, db, audit, cmds := newServiceForTest(t, time.Hour, time.Minute)
	oldTok := enrollOne(t, svc, testHostID)

	// First verify: stale -> rotation triggers, new token queued.
	ageToken(t, db, testHostID, 2*time.Hour)
	_, err := svc.VerifyToken(t.Context(), oldTok)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, int64(1), cmds.calls.Load())

	// Second verify with the OLD token: matches the previous-token grace
	// path. Service must NOT trigger another rotation.
	_, err = svc.VerifyToken(t.Context(), oldTok)
	require.NoError(t, err)
	assert.Len(t, audit.events, 1, "grace-path verify must not emit another audit row")
	assert.Equal(t, int64(1), cmds.calls.Load(), "grace-path verify must not queue another rotate_token command")
}

// RotateToken (operator path) force-rotates regardless of the token's
// age and emits an audit row tagged with trigger=operator + the
// supplied actor + reason fields.
func TestRotateToken_OperatorPath(t *testing.T) {
	svc, _, _, audit, cmds := newServiceForTest(t, 24*time.Hour, time.Minute)
	enrollOne(t, svc, testHostID) // intentionally fresh; operator override should still rotate

	res, err := svc.RotateToken(t.Context(), testHostID, api.RotationTriggerOperator,
		"victor@example", "incident-2026-Q2")
	require.NoError(t, err)
	assert.NotEmpty(t, res.PreviousTokenIDPrefix)
	assert.Positive(t, res.CommandID, "operator path must report the queued command_id")

	require.Len(t, audit.events, 1)
	got := audit.events[0]
	assert.Equal(t, "operator", got.Payload["trigger"])
	assert.Equal(t, "victor@example", got.Payload["actor"])
	assert.Equal(t, "incident-2026-Q2", got.Payload["reason"])
	assert.Equal(t, int64(1), cmds.calls.Load())
}

// Rotate on a missing host returns ErrNotFound (no audit, no command).
func TestRotateToken_MissingHost(t *testing.T) {
	svc, _, _, audit, cmds := newServiceForTest(t, 24*time.Hour, time.Minute)

	_, err := svc.RotateToken(t.Context(), "AAAA1111-2222-3333-4444-555566667777",
		api.RotationTriggerOperator, "operator", "test")
	require.ErrorIs(t, err, api.ErrNotFound)
	assert.Empty(t, audit.events)
	assert.Zero(t, cmds.calls.Load())
}

// Rotate against a revoked enrollment also surfaces as ErrNotFound:
// the row exists but is no longer eligible for rotation. Otherwise an
// attacker who has the (revoked) token could nudge the row back into
// a usable state.
func TestRotateToken_RevokedHost(t *testing.T) {
	svc, store, _, audit, cmds := newServiceForTest(t, 24*time.Hour, time.Minute)
	enrollOne(t, svc, testHostID)
	require.NoError(t, store.Revoke(t.Context(), testHostID, "compromised", "operator"))

	_, err := svc.RotateToken(t.Context(), testHostID, api.RotationTriggerOperator, "op", "test")
	require.ErrorIs(t, err, api.ErrNotFound)
	assert.Empty(t, audit.events)
	assert.Zero(t, cmds.calls.Load())
}

// RotateToken with both Audit and Commands nil must not panic; the
// service degrades gracefully (DB rotation still happens, audit + command
// emission no-op). This is the "tests / ingest binary" mode.
func TestRotateToken_NilDepsOK(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	svc := service.New(service.Options{
		Store:    mysql.NewStore(db),
		Secret:   testSecret,
		Lifetime: 24 * time.Hour,
		Grace:    time.Minute,
		Logger:   slog.Default(),
	})
	_, err := svc.Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: testSecret, HardwareUUID: testHostID,
		Hostname: "h", AgentVersion: "v", OSVersion: "o",
	}, "127.0.0.1")
	require.NoError(t, err)

	res, err := svc.RotateToken(t.Context(), testHostID, api.RotationTriggerOperator, "", "")
	require.NoError(t, err)
	assert.Zero(t, res.CommandID, "nil CommandInserter -> command_id 0")
	assert.NotEmpty(t, res.PreviousTokenIDPrefix)
}
