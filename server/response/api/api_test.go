package api_test

import (
	"encoding/json"
	"fmt"
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

// TestContainmentWireShapes pins the reviewed JSON of the containment wire types as literal text, beside the round trips above: a
// renamed or retagged field changes these bytes even when it still round-trips.
func TestContainmentWireShapes(t *testing.T) {
	t.Parallel()
	updated := time.Date(2026, 9, 15, 12, 52, 9, 21263000, time.UTC)
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"payload", api.SetNetworkContainmentPayload{Version: 2, Epoch: 1789476737910464, Contained: true},
			`{"version":2,"epoch":1789476737910464,"contained":true}`},
		{"a change with its delivery", api.ContainmentChange{
			State: api.ContainmentState{HostID: "H-1", Contained: true, Version: 1, Epoch: 1789476729021263, Reason: "beaconing",
				UpdatedBy: "usr_1", UpdatedAt: &updated, Delivery: &api.ContainmentDelivery{CommandID: 866, Status: api.StatusCompleted,
					Result: json.RawMessage(`{"applied":true}`), Current: true}},
			Changed: true, CommandID: 866,
		}, `{"state":{"host_id":"H-1","contained":true,"version":1,"epoch":1789476729021263,"reason":"beaconing","updated_by":"usr_1",` +
			`"updated_at":"2026-09-15T12:52:09.021263Z","delivery":{"command_id":866,"status":"completed","result":{"applied":true},` +
			`"current":true}},"changed":true,"command_id":866}`},
		{"a host never contained", api.ContainmentState{HostID: "H-2"}, `{"host_id":"H-2","contained":false,"version":0,"epoch":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}

// TestReachableWireTypesRoundTrip is the same round trip for the reachable-address set (issue #1059), which the containment command
// carries to hosts and the operator routes return.
//
// The empty-list case is the one worth the generator rather than a table: a set whose addresses marshal to `null` instead of `[]`
// would make "the operator removed every destination" read as "the field is missing" to any reader that distinguishes them, and an
// empty set is the state every deployment starts in.
func TestReachableWireTypesRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		count := rapid.IntRange(0, 6).Draw(rt, "count")
		in := api.ReachableSet{
			Version:   rapid.Int64().Draw(rt, "version"),
			UpdatedBy: rapid.String().Draw(rt, "updated_by"),
			Addresses: make([]api.ReachableAddress, 0, count),
		}
		for i := range count {
			in.Addresses = append(in.Addresses, api.ReachableAddress{
				CIDR:      rapid.StringN(1, 64, -1).Draw(rt, fmt.Sprintf("cidr_%d", i)),
				Port:      rapid.IntRange(0, 65535).Draw(rt, fmt.Sprintf("port_%d", i)),
				Transport: rapid.SampledFrom([]string{"", api.TransportTCP, api.TransportUDP}).Draw(rt, fmt.Sprintf("transport_%d", i)),
				Note:      rapid.String().Draw(rt, fmt.Sprintf("note_%d", i)),
			})
		}
		if rapid.Bool().Draw(rt, "has_time") {
			at := time.UnixMicro(rapid.Int64Range(0, 1<<50).Draw(rt, "updated_at")).UTC()
			in.UpdatedAt = &at
		}

		body, err := json.Marshal(in)
		require.NoError(rt, err)
		var out api.ReachableSet
		require.NoError(rt, json.Unmarshal(body, &out))
		assert.Equal(rt, in, out)
		assert.NotContains(rt, string(body), `"addresses":null`, "an empty set is an empty list, not a missing field")
	})
}
