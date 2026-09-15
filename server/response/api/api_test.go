package api_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/response/api"
)

// TestErrorSentinelsAreDistinct guards against two errors collapsing to the same value (which would make IsValidationError uselessly
// broad or errors.Is short-circuit incorrectly).
func TestErrorSentinelsAreDistinct(t *testing.T) {
	t.Parallel()
	require.NotErrorIs(t, api.ErrCommandNotFound, api.ErrInvalidStatusTransition)
	require.NotErrorIs(t, api.ErrInvalidStatusTransition, api.ErrInvalidInsertRequest)
	require.NotErrorIs(t, api.ErrCommandNotFound, api.ErrInvalidInsertRequest)
}

// TestIsValidationError covers every branch of the helper plus a
// negative case for ErrCommandNotFound (a 404, not a 400).
func TestIsValidationError(t *testing.T) {
	t.Parallel()
	assert.True(t, api.IsValidationError(api.ErrInvalidStatusTransition))
	assert.True(t, api.IsValidationError(api.ErrInvalidInsertRequest))
	assert.False(t, api.IsValidationError(api.ErrCommandNotFound))
	assert.False(t, api.IsValidationError(nil))
}

// TestStatusValuesMatchAgentWire locks the four status string values the agent's commander encodes/decodes against. Drifting any of
// them silently breaks every in-flight agent.
func TestStatusValuesMatchAgentWire(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "pending", string(api.StatusPending))
	assert.Equal(t, "acked", string(api.StatusAcked))
	assert.Equal(t, "completed", string(api.StatusCompleted))
	assert.Equal(t, "failed", string(api.StatusFailed))
}

// TestContainmentWireTypesRoundTrip is the round trip the testing-strategy matrix requires for new wire types: the command payload
// agents receive and the state, delivery and change the containment routes return.
func TestContainmentWireTypesRoundTrip(t *testing.T) {
	t.Parallel()
	roundTrip := func(rt *rapid.T, in, out any) {
		body, err := json.Marshal(in)
		require.NoError(rt, err)
		require.NoError(rt, json.Unmarshal(body, out))
	}
	t.Run("payload", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			in := api.SetNetworkContainmentPayload{
				Version: rapid.Int64().Draw(rt, "version"), Epoch: rapid.Int64().Draw(rt, "epoch"), Contained: rapid.Bool().Draw(rt, "contained"),
			}
			var out api.SetNetworkContainmentPayload
			roundTrip(rt, in, &out)
			assert.Equal(rt, in, out)
		})
	})
	t.Run("change", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			in := api.ContainmentChange{
				State: api.ContainmentState{
					HostID: rapid.StringN(1, 64, -1).Draw(rt, "host"), Contained: rapid.Bool().Draw(rt, "contained"),
					Version: rapid.Int64().Draw(rt, "version"), Epoch: rapid.Int64().Draw(rt, "epoch"),
					Reason: rapid.String().Draw(rt, "reason"), UpdatedBy: rapid.String().Draw(rt, "updated_by"),
				},
				Changed:   rapid.Bool().Draw(rt, "changed"),
				CommandID: rapid.Int64Min(0).Draw(rt, "command_id"),
			}
			if rapid.Bool().Draw(rt, "has_time") {
				at := time.UnixMicro(rapid.Int64Range(0, 1<<50).Draw(rt, "updated_at")).UTC()
				in.State.UpdatedAt = &at
			}
			if rapid.Bool().Draw(rt, "has_delivery") {
				status := rapid.SampledFrom([]string{"pending", "completed"}).Draw(rt, "status")
				in.State.Delivery = &api.ContainmentDelivery{
					CommandID: rapid.Int64().Draw(rt, "delivery_id"), Status: api.Status(status), Current: rapid.Bool().Draw(rt, "current"),
				}
				if rapid.Bool().Draw(rt, "has_result") {
					in.State.Delivery.Result = json.RawMessage(`{"applied":true}`)
				}
			}
			var out api.ContainmentChange
			roundTrip(rt, in, &out)
			assert.Equal(rt, in, out)
		})
	})
}
