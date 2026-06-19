package service_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/mysql"
	"github.com/fleetdm/edr/server/endpoint/internal/revocation"
	"github.com/fleetdm/edr/server/endpoint/internal/service"
	"github.com/fleetdm/edr/server/endpoint/internal/signedtoken"
	"github.com/fleetdm/edr/server/endpoint/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

const (
	testHostID = "93DFC6F5-763D-5075-B305-8AC145D12F96"
	testSecret = "test-enroll-secret"
)

// Fixed >=32-byte keys so a token minted at enroll verifies on a later call within the same test.
var (
	testPepper     = []byte("test-host-token-pepper-0123456789abcdef")
	testSigningKey = []byte("test-host-token-signing-0123456789abcdef")
)

// newServiceForTest stands up an endpoint Service over a real MySQL test DB, wired with the signer + revocation snapshot the
// self-validating-token model needs. The snapshot is returned so tests can Refresh it deterministically (production refreshes it on a
// ticker; tests drive it by hand to avoid sleeping).
func newServiceForTest(t *testing.T) (api.Service, *revocation.Snapshot) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := mysql.NewStore(db, testPepper)
	signer, err := signedtoken.New(testSigningKey, "v1")
	require.NoError(t, err)
	snap := revocation.NewSnapshot(store, slog.Default())
	svc := service.New(service.Options{
		Store:       store,
		Secret:      testSecret,
		Signer:      signer,
		Revocations: snap,
		TokenTTL:    time.Hour,
		Logger:      slog.Default(),
	})
	return svc, snap
}

func enrollForTest(t *testing.T, svc api.Service) api.EnrollResponse {
	t.Helper()
	res, err := svc.Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: testSecret,
		HardwareUUID: testHostID,
		Hostname:     "h",
		OSVersion:    "macOS 14",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)
	return res
}

// spec:agent-enrollment/host-tokens-are-self-validating-signed-tokens/issued-token-verifies-without-a-database-lookup
//
// TestEnroll_MintsVerifiableSignedToken: the enroll response carries a self-validating token that verifies, with an expiry about one
// TTL out.
func TestEnroll_MintsVerifiableSignedToken(t *testing.T) {
	t.Parallel()
	svc, _ := newServiceForTest(t)
	res := enrollForTest(t, svc)
	require.NotEmpty(t, res.HostToken)
	assert.WithinDuration(t, time.Now().Add(time.Hour), res.ExpiresAt, 2*time.Minute)

	hostID, err := svc.VerifyToken(t.Context(), res.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testHostID, hostID)
}

// TestRefreshToken_IssuesFreshVerifiableToken: with host_id pinned on the context (as the middleware does), refresh returns a new,
// distinct, verifiable token.
func TestRefreshToken_IssuesFreshVerifiableToken(t *testing.T) {
	t.Parallel()
	svc, _ := newServiceForTest(t)
	// Enroll to create the row; the refresh path reads it. We do not compare the refresh token to the enroll token: a same-second
	// refresh mints byte-identical claims (iat/exp are second-granular) and distinctness is not a requirement (both are equally valid).
	enrollForTest(t, svc)

	ctx := api.WithHostID(t.Context(), testHostID)
	ref, err := svc.RefreshToken(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, ref.HostToken)
	assert.Equal(t, testHostID, ref.HostID)

	hostID, err := svc.VerifyToken(t.Context(), ref.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testHostID, hostID)
}

// TestRefreshToken_UnknownHost: refresh for a host with no enrollment row is ErrInvalidToken (handler maps to 401 -> re-enroll).
func TestRefreshToken_UnknownHost(t *testing.T) {
	t.Parallel()
	svc, _ := newServiceForTest(t)
	ctx := api.WithHostID(t.Context(), "00000000-0000-0000-0000-000000000000")
	_, err := svc.RefreshToken(ctx)
	require.ErrorIs(t, err, api.ErrInvalidToken)
}

// spec:agent-enrollment/revocation-is-enforced-by-a-per-replica-snapshot/operator-rotate-invalidates-after-the-snapshot-refreshes
//
// TestRotateToken_BumpsEpochAndInvalidates: operator rotate bumps the epoch (no command pushed). After the snapshot refreshes, the
// pre-rotate token is rejected; a re-enroll mints a fresh token that verifies.
func TestRotateToken_BumpsEpochAndInvalidates(t *testing.T) {
	t.Parallel()
	svc, snap := newServiceForTest(t)
	res := enrollForTest(t, svc)
	require.NoError(t, snap.Refresh(t.Context()))
	_, err := svc.VerifyToken(t.Context(), res.HostToken)
	require.NoError(t, err)

	rot, err := svc.RotateToken(t.Context(), testHostID, api.RotationTriggerOperator, "victor@example", "incident-2026")
	require.NoError(t, err)
	assert.Nil(t, rot.CommandID, "no rotate_token command is pushed under the signed-token model")

	require.NoError(t, snap.Refresh(t.Context()))
	_, err = svc.VerifyToken(t.Context(), res.HostToken)
	require.ErrorIs(t, err, api.ErrInvalidToken, "pre-rotate token rejected once the epoch bump is visible")

	res2 := enrollForTest(t, svc)
	require.NoError(t, snap.Refresh(t.Context()))
	hostID, err := svc.VerifyToken(t.Context(), res2.HostToken)
	require.NoError(t, err, "re-enroll mints a fresh token at the reset epoch")
	assert.Equal(t, testHostID, hostID)
}

// TestRotateToken_NotFound: rotating a host with no enrollment is ErrNotFound.
func TestRotateToken_NotFound(t *testing.T) {
	t.Parallel()
	svc, _ := newServiceForTest(t)
	_, err := svc.RotateToken(t.Context(), "00000000-0000-0000-0000-000000000000", api.RotationTriggerOperator, "a", "b")
	require.ErrorIs(t, err, api.ErrNotFound)
}

// TestRevoke_InvalidatesAfterSnapshot: Revoke sets revoked_at; after the snapshot refreshes the token is rejected.
func TestRevoke_InvalidatesAfterSnapshot(t *testing.T) {
	t.Parallel()
	svc, snap := newServiceForTest(t)
	res := enrollForTest(t, svc)
	require.NoError(t, svc.Revoke(t.Context(), testHostID, "compromised", "op"))
	require.NoError(t, snap.Refresh(t.Context()))
	_, err := svc.VerifyToken(t.Context(), res.HostToken)
	require.ErrorIs(t, err, api.ErrInvalidToken)
}
