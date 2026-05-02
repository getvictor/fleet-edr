package mysql

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	srvbootstrap "github.com/fleetdm/edr/server/bootstrap"
)

const (
	testSecret = "test-enroll-secret"
	testUUID   = "93DFC6F5-763D-5075-B305-8AC145D12F96"
)

// enrollmentsDDLForTests duplicates the CREATE TABLE statement from
// server/endpoint/bootstrap/schema.go. Authoritative copy lives there;
// these mysql-package unit tests run before bootstrap.ApplySchema and
// would fail with "table doesn't exist" otherwise. Keep the schema here
// in lockstep with bootstrap/schema.go.
const enrollmentsDDLForTests = `CREATE TABLE IF NOT EXISTS enrollments (
	host_id          VARCHAR(255) PRIMARY KEY,
	host_token_id    VARBINARY(32)  NOT NULL,
	host_token_hash  VARBINARY(255) NOT NULL,
	host_token_salt  VARBINARY(32)  NOT NULL,
	hostname         VARCHAR(255)   NOT NULL,
	agent_version    VARCHAR(64)    NOT NULL,
	os_version       VARCHAR(128)   NOT NULL,
	source_ip        VARCHAR(45)    NOT NULL,
	enrolled_at      TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	expires_at       TIMESTAMP(6)   NULL,
	revoked_at       TIMESTAMP(6)   NULL,
	revoke_reason    VARCHAR(128)   NULL,
	revoked_by       VARCHAR(255)   NULL,
	UNIQUE KEY uk_enrollments_token_id (host_token_id)
)`

// newTestStore wraps srvbootstrap.OpenTestDB and exposes the raw sqlx.DB the
// enrollment Store needs. Applies the endpoint enrollments schema inline
// since these tests run below the bootstrap layer that would normally do it.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := srvbootstrap.OpenTestDB(t)
	if _, err := s.ExecContext(t.Context(), enrollmentsDDLForTests); err != nil {
		t.Fatalf("apply enrollments schema: %v", err)
	}
	return NewStore(s)
}

func TestHashRoundTrip(t *testing.T) {
	tok, err := generateToken()
	require.NoError(t, err)
	require.Len(t, tok, 43)

	hash, salt, err := hashToken(tok)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.Len(t, salt, argonSaltLen)

	assert.True(t, verifyToken(tok, hash, salt))
	assert.False(t, verifyToken("not-the-right-token-not-the-right-token-xxx", hash, salt))
	assert.False(t, verifyToken(tok, nil, salt))
	assert.False(t, verifyToken(tok, hash, nil))
}

func TestRegister_HappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	res, err := s.Register(ctx, RegisterRequest{
		HostID:       testUUID,
		Hostname:     "qa-host",
		AgentVersion: "0.0.1-dev",
		OSVersion:    "macOS 15.3",
		SourceIP:     "127.0.0.1",
	})
	require.NoError(t, err)
	assert.Equal(t, testUUID, res.HostID)
	assert.Len(t, res.HostToken, 43)
	assert.WithinDuration(t, time.Now(), res.EnrolledAt, 2*time.Second)

	// Verify the token round-trips.
	hostID, err := s.Verify(ctx, res.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, hostID)

	// An obviously-wrong token is rejected fast (length check short-circuits argon2).
	_, err = s.Verify(ctx, "nope")
	assert.ErrorIs(t, err, ErrTokenMismatch)
}

// TestVerify_LookupByTokenID exercises the SHA-256-keyed Verify path with a non-trivial
// number of enrollments. Asymptotic complexity can't be proven in a unit test; this just
// verifies correctness for many hosts in one DB, which a regression to the old full-table
// scan would still pass. The stronger O(1) contract is enforced at code-review time by
// pointing at the `WHERE host_token_id = ?` SQL in Verify.
func TestVerify_LookupByTokenID(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Register a handful of hosts so the active-enrollments table is non-trivial.
	want := make(map[string]string, 10)
	for i := range 10 {
		uuid := fmt.Sprintf("11111111-2222-3333-4444-%012d", i)
		res, err := s.Register(ctx, RegisterRequest{
			HostID: uuid, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
		})
		require.NoError(t, err)
		want[uuid] = res.HostToken
	}

	// Every real token resolves to its own host_id.
	for uuid, tok := range want {
		got, err := s.Verify(ctx, tok)
		require.NoError(t, err)
		assert.Equal(t, uuid, got)
	}

	// An unknown token with the correct length is ErrTokenMismatch — Verify must not
	// silently tolerate mis-shaped tokens by iterating the table.
	_, err := s.Verify(ctx, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	assert.ErrorIs(t, err, ErrTokenMismatch)
}

func TestRegister_ReenrollRevokesPrevious(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	first, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h1", AgentVersion: "v1", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	second, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h1-reimaged", AgentVersion: "v1", OSVersion: "o", SourceIP: "127.0.0.2",
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.HostToken, second.HostToken)

	// The previous token no longer validates.
	_, err = s.Verify(ctx, first.HostToken)
	require.ErrorIs(t, err, ErrTokenMismatch)

	// The current one does.
	hostID, err := s.Verify(ctx, second.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, hostID)
}

func TestList_RedactsTokenColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	_, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	// Round-trip through JSON: make sure no token material leaks.
	buf, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.NotContains(t, string(buf), "host_token")
	assert.NotContains(t, string(buf), "token_hash")
	assert.NotContains(t, string(buf), "token_salt")
}

func TestRevoke_IdempotentAndAfterwardsRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	reg, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	require.NoError(t, s.Revoke(ctx, testUUID, "compromised", "jane@customer.com"))

	// Token no longer verifies after revoke.
	_, err = s.Verify(ctx, reg.HostToken)
	require.ErrorIs(t, err, ErrTokenMismatch)

	// Second revoke is idempotent and preserves the first actor/reason.
	before, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, testUUID, "different-reason", "someoneElse"))
	after, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, before.RevokeReason, after.RevokeReason)
	assert.Equal(t, before.RevokedBy, after.RevokedBy)
	assert.Equal(t, before.RevokedAt.Unix(), after.RevokedAt.Unix())

	// Revoke for unknown host → sql.ErrNoRows.
	err = s.Revoke(ctx, "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "x", "y")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}
