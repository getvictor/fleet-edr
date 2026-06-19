package mysql_test

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/revocation"
	"github.com/fleetdm/edr/server/endpoint/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

// newTestStore opens an isolated DB and applies endpoint's schema via the canonical testkit.ApplySchema. Lives in the external test
// package so the testdb -> endpoint/bootstrap -> endpoint/internal/mysql cycle doesn't bite.
func newTestStore(t *testing.T) *mysql.Store {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return mysql.NewStore(db)
}

func register(t *testing.T, s *mysql.Store, hostID string) {
	t.Helper()
	_, err := s.Register(t.Context(), mysql.RegisterRequest{
		HostID: hostID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
}

func TestRegister_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	res, err := s.Register(t.Context(), mysql.RegisterRequest{
		HostID: testUUID, Hostname: "qa-host", AgentVersion: "0.0.1-dev", OSVersion: "macOS 15.3", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	assert.Equal(t, testUUID, res.HostID)
	assert.WithinDuration(t, time.Now(), res.EnrolledAt, 2*time.Second)

	// A fresh enrollment is at epoch 0 and not revoked.
	epoch, revoked, err := s.TokenStatus(t.Context(), testUUID)
	require.NoError(t, err)
	assert.Zero(t, epoch)
	assert.False(t, revoked)
}

// spec:agent-enrollment/revocation-is-enforced-by-a-per-replica-snapshot/re-enrollment-preserves-the-token-epoch
//
// TestRegister_ReenrollPreservesEpoch: a re-enroll updates the row in place and MUST NOT reset token_epoch (the old REPLACE INTO did,
// which let a stolen pre-rotate token validate again once the agent re-enrolled). It must, however, still clear revocation so a
// re-enrolled host is active again.
func TestRegister_ReenrollPreservesEpoch(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	register(t, s, testUUID)
	require.NoError(t, s.BumpTokenEpoch(ctx, testUUID))
	require.NoError(t, s.Revoke(ctx, testUUID, "x", "y"))

	res, err := s.Register(ctx, mysql.RegisterRequest{
		HostID: testUUID, Hostname: "h-reimaged", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.2",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), res.Epoch, "re-enroll returns the preserved epoch instead of resetting to 0")

	epoch, revoked, err := s.TokenStatus(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), epoch, "the DB row still carries the bumped epoch after re-enroll")
	assert.False(t, revoked, "re-enroll clears revoked_at")
}

func TestBumpTokenEpoch(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	register(t, s, testUUID)
	require.NoError(t, s.BumpTokenEpoch(ctx, testUUID))
	require.NoError(t, s.BumpTokenEpoch(ctx, testUUID))
	epoch, _, err := s.TokenStatus(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), epoch)

	assert.ErrorIs(t, s.BumpTokenEpoch(ctx, "00000000-0000-0000-0000-000000000000"), mysql.ErrNotFound)
}

func TestTokenStatus_NotFound(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	_, _, err := s.TokenStatus(t.Context(), "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, mysql.ErrNotFound)
}

// TestRevocationEntries: a clean host is excluded; an epoch-bumped host carries its epoch; a revoked host is flagged.
func TestRevocationEntries(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	clean := "11111111-1111-1111-1111-111111111111"
	bumped := "22222222-2222-2222-2222-222222222222"
	revoked := "33333333-3333-3333-3333-333333333333"
	register(t, s, clean)
	register(t, s, bumped)
	register(t, s, revoked)
	require.NoError(t, s.BumpTokenEpoch(ctx, bumped))
	require.NoError(t, s.Revoke(ctx, revoked, "compromised", "op"))

	entries, err := s.RevocationEntries(ctx)
	require.NoError(t, err)
	got := map[string]revocation.Entry{}
	for _, e := range entries {
		got[e.HostID] = e
	}
	assert.NotContains(t, got, clean, "clean host is not in the snapshot set")
	assert.Equal(t, int64(1), got[bumped].Epoch)
	assert.False(t, got[bumped].Revoked)
	assert.True(t, got[revoked].Revoked)
}

func TestList_Get(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	register(t, s, testUUID)

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, testUUID, rows[0].HostID)

	// No token material leaks through the JSON shape.
	buf, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.NotContains(t, string(buf), "host_token")
	assert.NotContains(t, string(buf), "token_hash")

	e, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, testUUID, e.HostID)

	_, err = s.Get(ctx, "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestCountActive_ActiveHostIDs(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	active := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	gone := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	register(t, s, active)
	register(t, s, gone)
	require.NoError(t, s.Revoke(ctx, gone, "x", "y"))

	n, err := s.CountActive(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ids, err := s.ActiveHostIDs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{active}, ids)
}

func TestRevoke_IdempotentAndUnknown(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()
	register(t, s, testUUID)

	require.NoError(t, s.Revoke(ctx, testUUID, "compromised", "jane@customer.com"))
	_, revoked, err := s.TokenStatus(ctx, testUUID)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Second revoke is idempotent and preserves the first actor/reason.
	before, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, testUUID, "different-reason", "someoneElse"))
	after, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, before.RevokeReason, after.RevokeReason)
	assert.Equal(t, before.RevokedBy, after.RevokedBy)

	assert.ErrorIs(t, s.Revoke(ctx, "00000000-0000-0000-0000-000000000000", "x", "y"), sql.ErrNoRows)
}
