//go:build integration

package breakglass_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newCredentialStore opens a fresh DB, applies identity schema, and seeds a placeholder admin user that webauthn_credentials can FK
// against. Returns the store + the seeded user id.
func newCredentialStore(t *testing.T) (*breakglass.CredentialStore, *sqlx.DB, int64) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	res, err := db.ExecContext(t.Context(),
		`INSERT INTO users (email, is_breakglass) VALUES (?, 1)`,
		"admin@fleet-edr.local")
	require.NoError(t, err)
	uid, err := res.LastInsertId()
	require.NoError(t, err)
	return breakglass.NewCredentialStore(db), db, uid
}

// fakeCredential builds a minimal webauthn.Credential the store can persist without requiring a real authenticator. The crypto fields
// are arbitrary bytes — the credential store does not verify them (that is go-webauthn's job in the ceremony layer).
func fakeCredential(id, pubkey string, signCount uint32) webauthn.Credential {
	return webauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte(pubkey),
		Transport: []protocol.AuthenticatorTransport{
			protocol.USB,
			protocol.NFC,
		},
		Authenticator: webauthn.Authenticator{
			SignCount: signCount,
		},
	}
}

// InsertWith persists the row + returns its id; round-trip via FindByID returns the same shape (transports, public_key, sign_count).
func TestCredentialStore_InsertAndFind(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-id-1", "pubkey-bytes", 5)

	id, err := s.InsertWith(t.Context(), db, uid, cred, "YubiKey-Slot-1")
	require.NoError(t, err)
	assert.Positive(t, id)

	got, err := s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)
	assert.Equal(t, uid, got.UserID)
	assert.Equal(t, cred.ID, got.CredentialID)
	assert.Equal(t, cred.PublicKey, got.PublicKey)
	assert.Equal(t, uint64(5), got.SignCount)
	assert.True(t, got.Name.Valid)
	assert.Equal(t, "YubiKey-Slot-1", got.Name.String)
	assert.True(t, got.Transports.Valid)
	assert.Contains(t, got.Transports.String, "usb")
	assert.Contains(t, got.Transports.String, "nfc")
}

// FindByID with an unknown id returns ErrCredentialNotFound, not a
// generic DB error.
func TestCredentialStore_FindByID_NotFound(t *testing.T) {
	s, _, _ := newCredentialStore(t)
	_, err := s.FindByID(t.Context(), []byte("never-existed"))
	assert.ErrorIs(t, err, breakglass.ErrCredentialNotFound)
}

// ListByUserID returns every credential for the user; an empty user
// returns an empty slice (not nil-slice-with-error).
func TestCredentialStore_ListByUserID(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	for i, suffix := range []string{"a", "b", "c"} {
		_, err := s.InsertWith(t.Context(), db, uid,
			fakeCredential("cred-"+suffix, "pk-"+suffix, uint32(i)), "")
		require.NoError(t, err)
	}
	rows, err := s.ListByUserID(t.Context(), uid)
	require.NoError(t, err)
	assert.Len(t, rows, 3)

	// Empty user yields empty slice.
	other, err := s.ListByUserID(t.Context(), uid+9999)
	require.NoError(t, err)
	assert.Empty(t, other)
}

// RecordAssertion bumps sign_count + last_used_at on a forward counter. Pinned because the bump is the storage half of WebAuthn's
// cloned-credential detection.
func TestCredentialStore_RecordAssertion_Forward(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-fwd", "pk", 5)
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	require.NoError(t, s.RecordAssertion(t.Context(), cred.ID, 7, false))

	got, err := s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), got.SignCount)
	assert.True(t, got.LastUsedAt.Valid)
}

// RecordAssertion rejects a sign_count regression with ErrCredentialClonedDetected — the central security signal of WebAuthn §6.1.1.
func TestCredentialStore_RecordAssertion_RejectsRegression(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-clone", "pk", 10)
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	err = s.RecordAssertion(t.Context(), cred.ID, 8, false)
	assert.ErrorIs(t, err, breakglass.ErrCredentialClonedDetected)

	// Equal sign_count is also a regression (counter must strictly advance — anything less suggests the authenticator was duplicated and
	// the clone re-played a previous assertion).
	err = s.RecordAssertion(t.Context(), cred.ID, 10, false)
	assert.ErrorIs(t, err, breakglass.ErrCredentialClonedDetected)
}

// RecordAssertion against a never-registered credential surfaces
// ErrCredentialNotFound, not the cloned-detection alarm.
func TestCredentialStore_RecordAssertion_Unknown(t *testing.T) {
	s, _, _ := newCredentialStore(t)
	err := s.RecordAssertion(t.Context(), []byte("ghost-cred"), 1, false)
	assert.ErrorIs(t, err, breakglass.ErrCredentialNotFound)
}

// RecordAssertion accepts SignCount=0 from a SignCount=0 stored credential. Many platform authenticators (Apple Touch ID Passkey,
// Google Password Manager) don't implement the counter and report 0 unconditionally. Per WebAuthn §6.1.1 a relying party SHOULD NOT
// treat this as a clone signal - the counter check only fires when the stored value is nonzero. Pinned because the previous shape
// (`WHERE ? > sign_count`) rejected this case incorrectly and broke every Touch ID Passkey login after first use.
func TestCredentialStore_RecordAssertion_ZeroCounterAccepted(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-touch-id", "pk", 0)
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	// Subsequent login also reports SignCount=0; must succeed.
	require.NoError(t, s.RecordAssertion(t.Context(), cred.ID, 0, false))
	got, err := s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), got.SignCount,
		"sign_count stays 0 when both stored and asserted are 0")
	assert.True(t, got.LastUsedAt.Valid, "last_used_at stamps on success")
}

// RecordAssertion persists backup_state flips from 0 to 1 - the "credential just got synced to iCloud Keychain" case. Spec allows BS
// to transition 0->1 over a credential's lifetime; the library already enforces 1->0 not allowed before this code runs.
func TestCredentialStore_RecordAssertion_BackupStateFlip(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-passkey", "pk", 1)
	// Register with BS=false.
	cred.Flags.BackupEligible = true
	cred.Flags.BackupState = false
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	got, err := s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	require.False(t, got.BackupState, "BS starts at the registered value")

	// Subsequent login reports BS=true (credential now backed up).
	require.NoError(t, s.RecordAssertion(t.Context(), cred.ID, 2, true))
	got, err = s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	assert.True(t, got.BackupState, "BS flips on the successful login that reported it")
	assert.True(t, got.BackupEligible, "BE remains invariant across login")
}

// Concurrent successful assertions must not roll the sign counter
// back: with the old read-then-write shape, two callers could SELECT
// the same stored counter and then race their UPDATEs, overwriting a
// higher counter with a lower one and weakening clone detection. The
// atomic GREATEST() write closes that window. Pinned so a future
// refactor doesn't accidentally reintroduce the TOCTOU.
//
// Likewise, backup_state must monotonically transition 0->1: a
// concurrent assertion that reports BS=false while another reports
// BS=true cannot regress the column. The `backup_state OR ?` write
// is what makes this safe.
func TestCredentialStore_RecordAssertion_ConcurrentMonotonic(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("cred-concurrent", "pk", 0)
	cred.Flags.BackupEligible = true
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	// Race two writers: one reports SignCount=100 + BS=true, one reports SignCount=50 + BS=false. Final state must be sign_count >= 100
	// AND BS=true regardless of execution order.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = s.RecordAssertion(t.Context(), cred.ID, 100, true)
	}()
	go func() {
		defer wg.Done()
		_ = s.RecordAssertion(t.Context(), cred.ID, 50, false)
	}()
	wg.Wait()

	got, err := s.FindByID(t.Context(), cred.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, got.SignCount, uint64(100),
		"sign_count must not roll back when two assertions race")
	assert.True(t, got.BackupState,
		"backup_state must stay true once any assertion reports it true")
}

// ToWebauthnCredentials converts a slice of stored rows into the shape go-webauthn expects on User.WebAuthnCredentials. Pinned because
// the conversion preserves transports + sign_count.
func TestToWebauthnCredentials(t *testing.T) {
	s, db, uid := newCredentialStore(t)
	cred := fakeCredential("conv-cred", "pk", 42)
	_, err := s.InsertWith(t.Context(), db, uid, cred, "")
	require.NoError(t, err)

	rows, err := s.ListByUserID(t.Context(), uid)
	require.NoError(t, err)
	out := breakglass.ToWebauthnCredentials(rows)
	require.Len(t, out, 1)
	assert.Equal(t, cred.ID, out[0].ID)
	assert.Equal(t, cred.PublicKey, out[0].PublicKey)
	assert.Equal(t, uint32(42), out[0].Authenticator.SignCount)
	transports := make([]string, 0, len(out[0].Transport))
	for _, t := range out[0].Transport {
		transports = append(transports, string(t))
	}
	assert.Truef(t,
		strings.Contains(strings.Join(transports, ","), "usb"),
		"transports must round-trip: got %v", transports)
}
