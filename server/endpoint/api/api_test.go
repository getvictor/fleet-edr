package api_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
)

func TestHostIDFromContext_RoundTrip(t *testing.T) {
	ctx := api.WithHostID(context.Background(), "host-abc")
	got, ok := api.HostIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "host-abc", got)
}

func TestHostIDFromContext_Empty(t *testing.T) {
	got, ok := api.HostIDFromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestHostIDFromContext_EmptyStringNotAuthenticated(t *testing.T) {
	// Pinning an empty host id should not be reported as authenticated. Guards against a writer accidentally passing "" and silently
	// authenticating a request without a real host id.
	ctx := api.WithHostID(context.Background(), "")
	got, ok := api.HostIDFromContext(ctx)
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestWithHostIDForTest_DelegatesToWithHostID(t *testing.T) {
	ctx := api.WithHostIDForTest(context.Background(), "host-xyz")
	got, ok := api.HostIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "host-xyz", got)
}

// TestErrorWrapChain verifies the error sentinels are not accidentally
// the same value (errors.Is would short-circuit incorrectly).
func TestErrorSentinelsAreDistinct(t *testing.T) {
	require.NotErrorIs(t, api.ErrInvalidSecret, api.ErrInvalidToken)
	require.NotErrorIs(t, api.ErrInvalidToken, api.ErrInvalidHardwareUUID)
	require.NotErrorIs(t, api.ErrInvalidHardwareUUID, api.ErrNotFound)
}
