package pipeline

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// TestMonitorTallyRoundTrips is the property the carry rests on: whatever an evaluating attempt resolved is what the withdrawing
// attempt records. The two attempts can be different processes running different builds across a rolling deploy, which is why the
// encoding is pinned by a round-trip over an input space rather than by one example.
func TestMonitorTallyRoundTrips(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		entries := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) rulesapi.MonitorMatch {
			return rulesapi.MonitorMatch{
				RuleID:   rapid.String().Draw(t, "rule_id"),
				HostID:   rapid.String().Draw(t, "host_id"),
				Severity: rapid.String().Draw(t, "severity"),
				Count:    rapid.Int().Draw(t, "count"),
			}
		}), 1, 20).Draw(t, "entries")

		encoded, err := encodeMonitorTally(entries)
		require.NoError(t, err)
		decoded, err := decodeMonitorTally(encoded)
		require.NoError(t, err)
		require.Equal(t, rulesapi.MonitorTally(entries), decoded)
	})
}

// TestEncodeMonitorTallyEmpty pins the distinction the whole fix turns on. An attempt with nothing to say hands over NOTHING, not
// an encoding of nothing, because the queue reads "no bytes" as "leave what is kept alone". An encoder that returned `[]` here
// would let an attempt that failed at the fold overwrite what an earlier attempt resolved, which is the defect, not the fix.
func TestEncodeMonitorTallyEmpty(t *testing.T) {
	t.Parallel()
	for _, empty := range []rulesapi.MonitorTally{nil, {}} {
		encoded, err := encodeMonitorTally(empty)
		require.NoError(t, err)
		assert.Nil(t, encoded, "an empty tally must be handed over as no bytes, so the queue keeps what it has")
	}
}

// TestEncodeMonitorTallyRefusesAnOversizedCarry covers the bound the queue's storage imposes. The queue REFUSES an oversized write
// rather than truncating it, and a refused write fails the nack and leaves the batch in flight until its claim lease expires. So
// an oversized tally has to cost the tally, and the caller finds that out here rather than from the database.
//
// The input is real rather than hypothetical: one entry per matching rule, and an imported rule pack is operator-sized and defaults
// to monitor mode, which is the population this carry exists for.
func TestEncodeMonitorTallyRefusesAnOversizedCarry(t *testing.T) {
	t.Parallel()

	// Sized from the bound rather than from a guessed count, so it stays a just-over-the-line input if either changes.
	const perEntry = 64
	oversized := make(rulesapi.MonitorTally, 0, visibilityapi.MaxNackTallyBytes/perEntry+2)
	for i := range cap(oversized) {
		oversized = append(oversized, rulesapi.MonitorMatch{
			RuleID: "imported-rule-" + strconv.Itoa(i), HostID: "host-a", Severity: "medium", Count: 1,
		})
	}
	// Measured, not assumed. A fixture that did not actually exceed the bound would make the assertion below pass against an
	// encoder with no bound at all, since a marshalling error and a bound refusal are both "an error".
	wire := monitorTallyV1{Version: monitorTallyVersion, Matches: make([]monitorMatchV1, len(oversized))}
	for i, m := range oversized {
		wire.Matches[i] = monitorMatchV1{RuleID: m.RuleID, HostID: m.HostID, Severity: m.Severity, Count: m.Count}
	}
	raw, err := json.Marshal(wire)
	require.NoError(t, err)
	require.Greater(t, len(raw), visibilityapi.MaxNackTallyBytes, "the fixture must actually exceed the bound")

	encoded, err := encodeMonitorTally(oversized)
	require.Error(t, err, "the caller must be told, not handed a write the queue would refuse")
	assert.Nil(t, encoded, "and must hand over no bytes, so the queue keeps whatever an earlier attempt supplied")

	// The bound is a ceiling, not a fixed size: a tally under it still encodes.
	within, err := encodeMonitorTally(oversized[:1])
	require.NoError(t, err)
	assert.NotEmpty(t, within)
}

// TestDecodeMonitorTallyRejectsWhatItCannotRead covers what the withdrawing attempt does with bytes it cannot use. They were
// written by another process, possibly another build, so unreadable is a state that has to have an answer.
func TestDecodeMonitorTallyRejectsWhatItCannotRead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		encoded []byte
		why     string
	}{
		{"not json", []byte("{"), "a truncated write must not be read as an empty tally, which would look like a clean zero"},
		{
			"a version this build does not know",
			[]byte(`{"v":99,"matches":[{"rule_id":"r","count":1}]}`),
			"a newer shape must be refused rather than read field by field into whatever happens to match",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decoded, err := decodeMonitorTally(tc.encoded)
			require.Error(t, err, tc.why)
			assert.Nil(t, decoded)
		})
	}

	// No bytes is not a failure. It is the ordinary state of a batch no attempt has evaluated.
	decoded, err := decodeMonitorTally(nil)
	require.NoError(t, err)
	assert.Empty(t, decoded)
}
