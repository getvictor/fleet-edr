package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/response/api"
)

// TestCanTransitionMatrix locks the 4x4 lifecycle table. Adding a
// new state means adding a row + column here.
func TestCanTransitionMatrix(t *testing.T) {
	cases := []struct {
		from, to api.Status
		want     bool
	}{
		// pending -> { acked, failed } legal; -> { pending, completed } illegal
		{api.StatusPending, api.StatusPending, false},
		{api.StatusPending, api.StatusAcked, true},
		{api.StatusPending, api.StatusCompleted, false},
		{api.StatusPending, api.StatusFailed, true},

		// acked -> { completed, failed } legal; -> { pending, acked } illegal
		{api.StatusAcked, api.StatusPending, false},
		{api.StatusAcked, api.StatusAcked, false},
		{api.StatusAcked, api.StatusCompleted, true},
		{api.StatusAcked, api.StatusFailed, true},

		// completed and failed are terminal -- no transitions out
		{api.StatusCompleted, api.StatusPending, false},
		{api.StatusCompleted, api.StatusAcked, false},
		{api.StatusCompleted, api.StatusCompleted, false},
		{api.StatusCompleted, api.StatusFailed, false},
		{api.StatusFailed, api.StatusPending, false},
		{api.StatusFailed, api.StatusAcked, false},
		{api.StatusFailed, api.StatusCompleted, false},
		{api.StatusFailed, api.StatusFailed, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.from)+"_to_"+string(tc.to), func(t *testing.T) {
			assert.Equal(t, tc.want, canTransition(tc.from, tc.to))
		})
	}
}

// TestValidTargetStatus locks the agent-supplied input vocabulary. pending is intentionally rejected -- the agent never asks the
// server to "un-ack" a command.
func TestValidTargetStatus(t *testing.T) {
	assert.False(t, validTargetStatus(api.StatusPending))
	assert.True(t, validTargetStatus(api.StatusAcked))
	assert.True(t, validTargetStatus(api.StatusCompleted))
	assert.True(t, validTargetStatus(api.StatusFailed))
	assert.False(t, validTargetStatus(api.Status("nonsense")))
}
