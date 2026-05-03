package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// allStatuses enumerates the alert lifecycle states the schema's
// ENUM accepts. Used by both the example-based + property-based
// tests below so they stay in lockstep with the schema.
var allStatuses = []api.AlertStatus{
	api.AlertStatusOpen,
	api.AlertStatusAcknowledged,
	api.AlertStatusResolved,
}

// allowedTransitions encodes the legal lifecycle matrix as the
// authoritative reference. Tests assert canTransition matches this
// set exactly. See server/detection/internal/service/service.go's
// UpdateAlertStatus docstring for the prose version.
var allowedTransitions = map[api.AlertStatus]map[api.AlertStatus]bool{
	api.AlertStatusOpen: {
		api.AlertStatusAcknowledged: true,
		api.AlertStatusResolved:     true,
	},
	api.AlertStatusAcknowledged: {
		api.AlertStatusOpen:     true,
		api.AlertStatusResolved: true,
	},
	api.AlertStatusResolved: {
		api.AlertStatusOpen: true,
	},
}

func TestCanTransition_ExampleMatrix(t *testing.T) {
	cases := []struct {
		from, to api.AlertStatus
		want     bool
	}{
		{api.AlertStatusOpen, api.AlertStatusAcknowledged, true},
		{api.AlertStatusOpen, api.AlertStatusResolved, true},
		{api.AlertStatusAcknowledged, api.AlertStatusResolved, true},
		{api.AlertStatusAcknowledged, api.AlertStatusOpen, true},
		{api.AlertStatusResolved, api.AlertStatusOpen, true},

		{api.AlertStatusResolved, api.AlertStatusAcknowledged, false},
		{api.AlertStatusOpen, api.AlertStatusOpen, false},
		{api.AlertStatusAcknowledged, api.AlertStatusAcknowledged, false},
		{api.AlertStatusResolved, api.AlertStatusResolved, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.from)+"_to_"+string(tc.to), func(t *testing.T) {
			assert.Equal(t, tc.want, canTransition(tc.from, tc.to))
		})
	}
}

// TestCanTransition_MatchesAllowedTransitionsProperty:
// canTransition(from, to) == allowedTransitions[from][to] for every
// pair (from, to) in the AlertStatus enum cross-product. PBT here
// means rapid samples the cross-product exhaustively across runs;
// any future drift between canTransition's switch and the
// allowedTransitions reference table fails the property loudly,
// with a shrunken counter-example naming the exact (from, to) pair.
func TestCanTransition_MatchesAllowedTransitionsProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		from := rapid.SampledFrom(allStatuses).Draw(rt, "from")
		to := rapid.SampledFrom(allStatuses).Draw(rt, "to")
		want := allowedTransitions[from][to]
		assert.Equal(rt, want, canTransition(from, to),
			"canTransition(%s, %s) must equal the allowedTransitions reference", from, to)
	})
}

// TestCanTransition_NeverFromUnknownState pins the "every undefined
// state rejects all transitions" behaviour: passing a status the
// service has never seen returns false, regardless of target.
func TestCanTransition_NeverFromUnknownState(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// "" and any string outside the enum are unknown states.
		unknown := api.AlertStatus(rapid.StringMatching(`(?:|x[a-z]{0,8}|some_other_state)`).Draw(rt, "unknown"))
		// Skip if rapid happens to draw a known state via the empty branch.
		for _, s := range allStatuses {
			if unknown == s {
				rt.Skip("drew a known state")
			}
		}
		to := rapid.SampledFrom(allStatuses).Draw(rt, "to")
		assert.False(rt, canTransition(unknown, to),
			"unknown state %q must never transition", string(unknown))
	})
}
