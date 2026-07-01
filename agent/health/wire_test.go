package health

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestReport_WirePin pins the exact bytes the agent POSTs to /api/status so the agent side of the contract cannot drift silently: field
// names, the closed status spelling, and the omitempty behaviour of reason/message. It mirrors the server's TestStatusReport_WirePin
// (server/endpoint/api); the two sides define the wire independently, so both pin it. The security extension is the #359
// never-connected case; the network extension is healthy with an empty message (message omitted).
func TestReport_WirePin(t *testing.T) {
	t.Parallel()
	r := report{
		AgentVersion: "0.4.0",
		ReportedAtNs: 1700000000000000000,
		Components: []Component{
			{Type: ComponentEndpointSecurityExtension, Status: StatusUnhealthy, Reason: reasonNeverConnected, Message: "Security extension not activated", LastTransitionNs: 1699999999000000000},
			{Type: ComponentNetworkExtension, Status: StatusHealthy, Reason: reasonActivated, LastTransitionNs: 1699999998000000000},
		},
	}
	out, err := json.Marshal(r)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"agent_version": "0.4.0",
		"reported_at_ns": 1700000000000000000,
		"components": [
			{"type":"endpoint_security_extension","status":"unhealthy","reason":"never_connected","message":"Security extension not activated","last_transition_ns":1699999999000000000},
			{"type":"network_extension","status":"healthy","reason":"activated","last_transition_ns":1699999998000000000}
		]
	}`, string(out))
}

func componentGen() *rapid.Generator[Component] {
	statuses := []Status{StatusHealthy, StatusDegraded, StatusUnhealthy, StatusUnknown}
	return rapid.Custom(func(rt *rapid.T) Component {
		return Component{
			Type:             rapid.StringMatching(`[a-z_]{1,24}`).Draw(rt, "type"),
			Status:           rapid.SampledFrom(statuses).Draw(rt, "status"),
			Reason:           rapid.StringMatching(`[a-z_]{0,24}`).Draw(rt, "reason"),
			Message:          rapid.StringMatching(`[ -~]{0,40}`).Draw(rt, "message"),
			LastTransitionNs: rapid.Int64().Draw(rt, "last_transition_ns"),
		}
	})
}

// TestReport_RoundTripProperty: Unmarshal(Marshal(r)) == r for any report. Guards the new wire struct against a lossy or reordered
// field on either the marshal or unmarshal side (CLAUDE.md: new wire-format struct gets a PBT round-trip).
func TestReport_RoundTripProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		comps := rapid.SliceOfN(componentGen(), 0, 6).Draw(rt, "components")
		if len(comps) == 0 {
			comps = nil // JSON null decodes to a nil slice, never to an empty non-nil slice; normalise so require.Equal holds.
		}
		original := report{
			AgentVersion: rapid.StringMatching(`[ -~]{0,16}`).Draw(rt, "agent_version"),
			ReportedAtNs: rapid.Int64().Draw(rt, "reported_at_ns"),
			Components:   comps,
		}
		out, err := json.Marshal(original)
		require.NoError(rt, err)
		var back report
		require.NoError(rt, json.Unmarshal(out, &back))
		assert.Equal(rt, original, back)
	})
}
