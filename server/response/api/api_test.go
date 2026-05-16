package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/api"
)

// TestErrorSentinelsAreDistinct guards against two errors collapsing to the same value (which would make IsValidationError uselessly
// broad or errors.Is short-circuit incorrectly).
func TestErrorSentinelsAreDistinct(t *testing.T) {
	require.NotErrorIs(t, api.ErrCommandNotFound, api.ErrInvalidStatusTransition)
	require.NotErrorIs(t, api.ErrInvalidStatusTransition, api.ErrInvalidInsertRequest)
	require.NotErrorIs(t, api.ErrCommandNotFound, api.ErrInvalidInsertRequest)
}

// TestIsValidationError covers every branch of the helper plus a
// negative case for ErrCommandNotFound (a 404, not a 400).
func TestIsValidationError(t *testing.T) {
	assert.True(t, api.IsValidationError(api.ErrInvalidStatusTransition))
	assert.True(t, api.IsValidationError(api.ErrInvalidInsertRequest))
	assert.False(t, api.IsValidationError(api.ErrCommandNotFound))
	assert.False(t, api.IsValidationError(nil))
}

// TestStatusValuesMatchAgentWire locks the four status string values the agent's commander encodes/decodes against. Drifting any of
// them silently breaks every in-flight agent.
func TestStatusValuesMatchAgentWire(t *testing.T) {
	assert.Equal(t, "pending", string(api.StatusPending))
	assert.Equal(t, "acked", string(api.StatusAcked))
	assert.Equal(t, "completed", string(api.StatusCompleted))
	assert.Equal(t, "failed", string(api.StatusFailed))
}
