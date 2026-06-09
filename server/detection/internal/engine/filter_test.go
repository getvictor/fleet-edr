package engine

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// ---- Example-based tests --------------------------------------------------

func TestIsSnapshotExec(t *testing.T) {
	cases := []struct {
		name string
		evt  api.Event
		want bool
	}{
		{
			name: "non-exec event_type returns false",
			evt:  api.Event{EventType: "fork", Payload: json.RawMessage(`{"snapshot":true}`)},
			want: false,
		},
		{
			name: "exec without snapshot field returns false",
			evt:  api.Event{EventType: "exec", Payload: json.RawMessage(`{"path":"/bin/ls"}`)},
			want: false,
		},
		{
			name: "exec with snapshot=true returns true",
			evt:  api.Event{EventType: "exec", Payload: json.RawMessage(`{"snapshot":true}`)},
			want: true,
		},
		{
			name: "exec with snapshot=false returns false",
			evt:  api.Event{EventType: "exec", Payload: json.RawMessage(`{"snapshot":false}`)},
			want: false,
		},
		{
			name: "exec with malformed payload returns false",
			evt:  api.Event{EventType: "exec", Payload: json.RawMessage(`{not json`)},
			want: false,
		},
		{
			name: "exec with snapshot key elsewhere returns false (probe truth)",
			evt:  api.Event{EventType: "exec", Payload: json.RawMessage(`{"path":"/bin/snapshot/x"}`)},
			want: false,
		},
		{
			// Negative guard - isSnapshotExec is exec-only, not the generic plumbing filter.
			// snapshot_heartbeat events are handled by isPlumbingEvent's switch arm.
			name: "snapshot_heartbeat is NOT a snapshot exec",
			evt:  api.Event{EventType: "snapshot_heartbeat", Payload: json.RawMessage(`{"pid":1}`)},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSnapshotExec(tc.evt))
		})
	}
}

func TestFilterSnapshotEvents_DropsHeartbeats(t *testing.T) {
	// Issue #173: snapshot_heartbeat events are pure liveness plumbing. They must not reach rule evaluation, otherwise rules would
	// have to remember to skip a no-op event type that carries only a pid and a timestamp.
	in := []api.Event{
		{EventID: "fork-1", EventType: "fork", Payload: json.RawMessage(`{}`)},
		{EventID: "hb-1", EventType: "snapshot_heartbeat", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "exec-1", EventType: "exec", Payload: json.RawMessage(`{"path":"/bin/x"}`)},
		{EventID: "hb-2", EventType: "snapshot_heartbeat", Payload: json.RawMessage(`{"pid":2}`)},
	}
	out := filterSnapshotEvents(in)
	require.Len(t, out, 2, "both heartbeats must be dropped, fork + exec kept")
	assert.Equal(t, "fork-1", out[0].EventID)
	assert.Equal(t, "exec-1", out[1].EventID)
}

func TestFilterSnapshotEvents_Empty(t *testing.T) {
	assert.Empty(t, filterSnapshotEvents(nil))
	assert.Empty(t, filterSnapshotEvents([]api.Event{}))
}

func TestFilterSnapshotEvents_NoSnapshotsReturnsInputVerbatim(t *testing.T) {
	in := []api.Event{
		{EventID: "1", EventType: "fork", Payload: json.RawMessage(`{}`)},
		{EventID: "2", EventType: "exec", Payload: json.RawMessage(`{"path":"/bin/ls"}`)},
	}
	out := filterSnapshotEvents(in)
	require.Len(t, out, 2)
	// Same backing slice when no copy is required.
	assert.Equal(t, in[0].EventID, out[0].EventID)
	assert.Equal(t, in[1].EventID, out[1].EventID)
}

// ---- Property-based tests -------------------------------------------------

// eventForFilterGen produces events whose payloads exercise every branch of the plumbing
// filter (issue #173 broadened the filter from snapshot-exec only to all plumbing events).
// Each generated event has one of these shapes:
//
//   - non-exec, non-heartbeat events (filter must keep)
//   - exec without snapshot field (keep)
//   - exec with snapshot:true (drop)
//   - exec with snapshot:false (keep)
//   - exec with malformed payload + snapshot in path (keep; the bytes.Contains fast-path
//     misses and the JSON probe fails)
//   - snapshot_heartbeat event (drop -- pure liveness plumbing)
func eventForFilterGen() *rapid.Generator[api.Event] {
	return rapid.Custom(func(t *rapid.T) api.Event {
		shape := rapid.IntRange(0, 5).Draw(t, "shape")
		evt := api.Event{
			EventID: rapid.StringMatching(`[a-z0-9]{1,8}`).Draw(t, "id"),
			HostID:  "h",
		}
		switch shape {
		case 0:
			evt.EventType = rapid.SampledFrom([]string{"fork", "exit", "open", "network_connect", "dns_query"}).Draw(t, "non_exec_type")
			evt.Payload = json.RawMessage(`{}`)
		case 1:
			evt.EventType = "exec"
			evt.Payload = json.RawMessage(`{"path":"/bin/ls"}`)
		case 2:
			evt.EventType = "exec"
			evt.Payload = json.RawMessage(`{"snapshot":true,"path":"/bin/ls"}`)
		case 3:
			evt.EventType = "exec"
			evt.Payload = json.RawMessage(`{"snapshot":false,"path":"/bin/ls"}`)
		case 4:
			evt.EventType = "exec"
			evt.Payload = json.RawMessage(`{"path":"/bin/snapshot"}`)
		case 5:
			evt.EventType = "snapshot_heartbeat"
			evt.Payload = json.RawMessage(`{"pid":` + rapid.StringMatching(`[1-9][0-9]{0,4}`).Draw(t, "pid") + `}`)
		}
		return evt
	})
}

// TestFilterSnapshotEvents_PropertyDropsOnlySnapshotsAndPreservesOrder
// asserts two invariants on every random batch:
//
//  1. The output equals the input minus exactly the plumbing events
//     (snapshot=true exec + snapshot_heartbeat).
//  2. The kept events appear in the same order as in the input.
//
// PBT here is the natural fit because the input space is "any permutation of any subset
// of events of the six shapes above" -- far larger than a table-driven test reasonably
// covers, and shrinking gives a minimal counter-example on failure. Predicate matches
// the filter's `isPlumbingEvent` rather than the narrower `isSnapshotExec` so the
// expected output reflects both kinds of drops.
func TestFilterSnapshotEvents_PropertyDropsOnlySnapshotsAndPreservesOrder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		in := rapid.SliceOfN(eventForFilterGen(), 0, 16).Draw(rt, "in")
		out := filterSnapshotEvents(in)

		expected := make([]api.Event, 0, len(in))
		for _, e := range in {
			if !isPlumbingEvent(e) {
				expected = append(expected, e)
			}
		}

		require.Len(rt, out, len(expected),
			"output length must equal input minus plumbing events")
		for i := range expected {
			assert.Equal(rt, expected[i].EventID, out[i].EventID,
				"order preservation: kept event at i=%d must match expected", i)
		}
	})
}

// TestFilterSnapshotEvents_PropertyIdempotent: applying the filter twice yields the same result as applying it once. A second
// pass must not drop anything new (every kept event is non-snapshot by construction) and must not re-add anything (the filter is a
// projection).
func TestFilterSnapshotEvents_PropertyIdempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		in := rapid.SliceOfN(eventForFilterGen(), 0, 16).Draw(rt, "in")
		once := filterSnapshotEvents(in)
		twice := filterSnapshotEvents(once)
		require.Len(rt, twice, len(once))
		for i := range once {
			assert.Equal(rt, once[i].EventID, twice[i].EventID)
		}
	})
}
