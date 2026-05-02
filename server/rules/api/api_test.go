package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestErrorSentinelsAreDistinct guards against two errors collapsing to
// the same value (which would make IsValidationError uselessly broad
// or errors.Is short-circuit incorrectly).
func TestErrorSentinelsAreDistinct(t *testing.T) {
	require.NotErrorIs(t, api.ErrInvalidPath, api.ErrInvalidHash)
	require.NotErrorIs(t, api.ErrInvalidHash, api.ErrInvalidUpdateRequest)
	require.NotErrorIs(t, api.ErrInvalidPath, api.ErrPolicyNotFound)
	require.NotErrorIs(t, api.ErrPolicyNotFound, api.ErrInvalidUpdateRequest)
}

// TestIsValidationError covers every branch of the helper plus a
// negative case for non-validation sentinels.
func TestIsValidationError(t *testing.T) {
	assert.True(t, api.IsValidationError(api.ErrInvalidPath))
	assert.True(t, api.IsValidationError(api.ErrInvalidHash))
	assert.True(t, api.IsValidationError(api.ErrInvalidUpdateRequest))
	assert.False(t, api.IsValidationError(api.ErrPolicyNotFound))
	assert.False(t, api.IsValidationError(nil))
}

// TestMarshalSetBlocklistPayload locks the agent wire shape. If a
// future refactor accidentally renames a JSON field on
// SetBlocklistPayload the existing agents in the field would break;
// this asserts the bytes are byte-identical with what
// admin.policyCommandPayload produced today.
func TestMarshalSetBlocklistPayload(t *testing.T) {
	payload, err := api.MarshalSetBlocklistPayload(api.BlocklistPolicy{
		Name:    "default",
		Version: 7,
		Blocklist: api.Blocklist{
			Paths:  []string{"/private/tmp/blocked"},
			Hashes: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	})
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"name":"default","version":7,"paths":["/private/tmp/blocked"],"hashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}`,
		string(payload),
	)
}
