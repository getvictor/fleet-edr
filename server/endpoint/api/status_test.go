package api_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/endpoint/api"
)

// TestStatusReport_WirePin pins the exact on-the-wire JSON the agent sends, so the agent contract cannot drift silently: the field
// names, the closed status spelling, and the omitempty behaviour of reason/message. The security extension is the #359 never-connected
// case; the network extension is healthy with an empty message (message omitted).
func TestStatusReport_WirePin(t *testing.T) {
	t.Parallel()
	report := api.StatusReport{
		AgentVersion: "0.4.0",
		ReportedAtNs: 1700000000000000000,
		Components: api.Components{
			{
				Type:             api.ComponentEndpointSecurityExtension,
				Status:           api.HealthUnhealthy,
				Reason:           api.ReasonNeverConnected,
				Message:          "security extension not activated",
				LastTransitionNs: 1699999999000000000,
			},
			{
				Type:             api.ComponentNetworkExtension,
				Status:           api.HealthHealthy,
				Reason:           api.ReasonActivated,
				LastTransitionNs: 1699999998000000000,
			},
		},
	}

	out, err := json.Marshal(report)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"agent_version": "0.4.0",
		"reported_at_ns": 1700000000000000000,
		"components": [
			{
				"type": "endpoint_security_extension",
				"status": "unhealthy",
				"reason": "never_connected",
				"message": "security extension not activated",
				"last_transition_ns": 1699999999000000000
			},
			{
				"type": "network_extension",
				"status": "healthy",
				"reason": "activated",
				"last_transition_ns": 1699999998000000000
			}
		]
	}`, string(out))
}

func TestHealthStatus_Valid(t *testing.T) {
	t.Parallel()
	for _, s := range []api.HealthStatus{api.HealthHealthy, api.HealthDegraded, api.HealthUnhealthy, api.HealthUnknown} {
		assert.Truef(t, s.Valid(), "%q must be valid", s)
	}
	for _, s := range []api.HealthStatus{"", "ok", "HEALTHY", "down", "unknown "} {
		assert.Falsef(t, s.Valid(), "%q must be invalid", s)
	}
}

func TestComponents_Scan(t *testing.T) {
	t.Parallel()

	fromNil := api.Components(nil)
	require.NoError(t, fromNil.Scan(nil))
	assert.Nil(t, fromNil, "SQL NULL scans to a nil slice")

	fromEmpty := api.Components(nil)
	require.NoError(t, fromEmpty.Scan([]byte{}))
	assert.Nil(t, fromEmpty, "an empty payload scans to a nil slice")

	fromBytes := api.Components(nil)
	require.NoError(t, fromBytes.Scan([]byte(`[{"type":"network_extension","status":"healthy","last_transition_ns":7}]`)))
	assert.Equal(t, api.Components{{Type: api.ComponentNetworkExtension, Status: api.HealthHealthy, LastTransitionNs: 7}}, fromBytes)

	fromStr := api.Components(nil)
	require.NoError(t, fromStr.Scan(`[{"type":"x","status":"unknown","last_transition_ns":0}]`))
	assert.Equal(t, api.Components{{Type: "x", Status: api.HealthUnknown}}, fromStr)

	bad := api.Components(nil)
	err := bad.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

// TestRollup covers the server-side worst-of rollup across the status precedence.
//
// spec:server-host-status/the-server-computes-an-overall-host-health-rollup/one-unhealthy-component-makes-the-host-unhealthy
// spec:server-host-status/the-server-computes-an-overall-host-health-rollup/a-host-with-no-snapshot-rolls-up-to-unknown
// spec:server-host-status/the-server-computes-an-overall-host-health-rollup/all-healthy-components-roll-up-to-healthy
func TestRollup(t *testing.T) {
	t.Parallel()
	comp := func(s api.HealthStatus) api.ComponentHealth { return api.ComponentHealth{Type: "c", Status: s} }
	cases := []struct {
		name string
		in   api.Components
		want api.HealthStatus
	}{
		{"nil is unknown", nil, api.HealthUnknown},
		{"empty is unknown", api.Components{}, api.HealthUnknown},
		{"all healthy is healthy", api.Components{comp(api.HealthHealthy), comp(api.HealthHealthy)}, api.HealthHealthy},
		{"one unhealthy is unhealthy", api.Components{comp(api.HealthHealthy), comp(api.HealthUnhealthy)}, api.HealthUnhealthy},
		{"one degraded is degraded", api.Components{comp(api.HealthHealthy), comp(api.HealthDegraded)}, api.HealthDegraded},
		{"unhealthy beats degraded", api.Components{comp(api.HealthDegraded), comp(api.HealthUnhealthy)}, api.HealthUnhealthy},
		{"unhealthy first still unhealthy", api.Components{comp(api.HealthUnhealthy), comp(api.HealthDegraded)}, api.HealthUnhealthy},
		{"lone unknown component rolls up healthy", api.Components{comp(api.HealthUnknown)}, api.HealthHealthy},
		{"healthy plus unknown is healthy", api.Components{comp(api.HealthHealthy), comp(api.HealthUnknown)}, api.HealthHealthy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.Rollup(tc.in))
		})
	}
}

func TestComponents_Value(t *testing.T) {
	t.Parallel()

	v, err := api.Components(nil).Value()
	require.NoError(t, err)
	assert.Nil(t, v, "a nil slice maps to SQL NULL")

	v, err = api.Components{}.Value()
	require.NoError(t, err)
	assert.Nil(t, v, "an empty slice maps to SQL NULL")

	v, err = api.Components{{Type: "x", Status: api.HealthHealthy, LastTransitionNs: 3}}.Value()
	require.NoError(t, err)
	assert.JSONEq(t, `[{"type":"x","status":"healthy","last_transition_ns":3}]`, string(v.([]byte)))
}

// ---- Property-based tests --------------------------------------------------

func componentGen() *rapid.Generator[api.ComponentHealth] {
	return rapid.Custom(func(rt *rapid.T) api.ComponentHealth {
		return api.ComponentHealth{
			Type:             rapid.StringMatching(`[a-z_]{1,24}`).Draw(rt, "type"),
			Status:           rapid.SampledFrom([]api.HealthStatus{api.HealthHealthy, api.HealthDegraded, api.HealthUnhealthy, api.HealthUnknown}).Draw(rt, "status"),
			Reason:           rapid.StringMatching(`[a-z_]{0,24}`).Draw(rt, "reason"),
			Message:          rapid.StringMatching(`[ -~]{0,32}`).Draw(rt, "message"),
			LastTransitionNs: rapid.Int64().Draw(rt, "last_transition_ns"),
		}
	})
}

// componentsGen normalises a zero-length draw to a nil slice so the round-trip identities below hold under require.Equal (SQL NULL and
// JSON null both decode to nil, never to an empty non-nil slice).
func componentsGen() *rapid.Generator[api.Components] {
	return rapid.Custom(func(rt *rapid.T) api.Components {
		s := rapid.SliceOfN(componentGen(), 0, 6).Draw(rt, "components")
		if len(s) == 0 {
			return nil
		}
		return api.Components(s)
	})
}

// TestStatusReport_RoundTripProperty: Unmarshal(Marshal(r)) == r for any report. The wire contract must not lose or mangle a field.
func TestStatusReport_RoundTripProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		report := api.StatusReport{
			AgentVersion: rapid.StringMatching(`[ -~]{0,16}`).Draw(rt, "agent_version"),
			ReportedAtNs: rapid.Int64().Draw(rt, "reported_at_ns"),
			Components:   componentsGen().Draw(rt, "components"),
		}

		out, err := json.Marshal(report)
		require.NoError(rt, err)

		var back api.StatusReport
		require.NoError(rt, json.Unmarshal(out, &back))
		assert.Equal(rt, report, back)
	})
}

// TestComponents_ScanValueProperty: Scan(Value(c)) == c with the empty-slice collapse to nil that Value applies.
func TestComponents_ScanValueProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		original := componentsGen().Draw(rt, "components")

		val, err := original.Value()
		require.NoError(rt, err)

		rebuilt := api.Components(nil)
		if val == nil {
			require.NoError(rt, rebuilt.Scan(nil))
			assert.Nil(rt, rebuilt)
			return
		}
		require.NoError(rt, rebuilt.Scan(val.([]byte)))
		assert.Equal(rt, original, rebuilt)
	})
}
