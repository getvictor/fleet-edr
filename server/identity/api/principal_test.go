package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestPrincipalIDRoundTrip is the serialization round-trip property from the testing-strategy matrix: minting a principal id from a
// numeric key and reading it back recovers the same key and type, across the whole positive-int64 input space.
func TestPrincipalIDRoundTrip(t *testing.T) {
	t.Run("user id round-trips through UserID", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			id := rapid.Int64Range(1, 1<<62).Draw(rt, "userID")
			ref := UserPrincipal(id, "op@example.com")
			got, ok := ref.UserID()
			require.True(rt, ok, "a freshly minted user principal must parse back")
			assert.Equal(rt, id, got)
			typ, ok := PrincipalTypeForID(ref.ID)
			require.True(rt, ok)
			assert.Equal(rt, PrincipalUser, typ)
		})
	})

	t.Run("service-account id carries the service_account type", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			id := rapid.Int64Range(1, 1<<62).Draw(rt, "saID")
			ref := ServiceAccountPrincipal(id, "ci-bot")
			typ, ok := PrincipalTypeForID(ref.ID)
			require.True(rt, ok)
			assert.Equal(rt, PrincipalServiceAccount, typ)
			_, isUser := ref.UserID()
			assert.False(rt, isUser, "a service-account principal must never read as a user")
		})
	})
}

// TestPrincipalRefUserID pins the exact accepted and rejected shapes of the user-id accessor, the security-relevant boundary that keeps
// a service account from ever being treated as a user.
func TestPrincipalRefUserID(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		wantID int64
		wantOK bool
	}{
		{"well-formed user id", UserPrincipalID(42), 42, true},
		{"service-account id rejected", ServiceAccountPrincipalID(42), 0, false},
		{"system id rejected", PrincipalSystemID, 0, false},
		{"empty id rejected", "", 0, false},
		{"non-numeric local part rejected", "usr_abc", 0, false},
		{"ULID-shaped local part rejected", "usr_01J9Z3ABCD", 0, false},
		{"zero user id rejected", "usr_0", 0, false},
		{"negative user id rejected", "usr_-1", 0, false},
		{"bare prefix rejected", "usr_", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PrincipalRef{ID: tc.id}.UserID()
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantID, got)
		})
	}
}

// TestPrincipalTypeForID covers the read-side type recovery, including the legacy/malformed values the migration backfill must not
// produce but the parser must reject rather than misclassify.
func TestPrincipalTypeForID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want PrincipalType
		ok   bool
	}{
		{"user", UserPrincipalID(1), PrincipalUser, true},
		{"service account", ServiceAccountPrincipalID(1), PrincipalServiceAccount, true},
		{"system", PrincipalSystemID, PrincipalSystem, true},
		{"legacy user:<id> rejected", "user:1", "", false},
		{"legacy system literal rejected", "system", "", false},
		{"empty rejected", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PrincipalTypeForID(tc.id)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSystemPrincipal pins the singleton system principal's shape.
func TestSystemPrincipal(t *testing.T) {
	sys := SystemPrincipal()
	assert.Equal(t, PrincipalSystemID, sys.ID)
	assert.Equal(t, PrincipalSystem, sys.Type)
	assert.Equal(t, "system", sys.Label)
	_, isUser := sys.UserID()
	assert.False(t, isUser)
}
