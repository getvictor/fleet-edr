package sigmabind

import (
	"encoding/json"
	"testing"

	"github.com/fleetdm/edr/server/rules/api"
)

// benchExecEvent is a representative exec event: a real path and an argument vector long enough that the argv derivations
// (command line, subcommand, arguments, env assignments) do the work they do in production rather than a degenerate amount of it.
func benchExecEvent(tb testing.TB) api.Event {
	tb.Helper()

	payload, err := json.Marshal(map[string]any{
		"pid":  4242,
		"path": "/usr/bin/curl",
		"args": []string{"curl", "-fsSL", "-H", "Authorization: Bearer abc", "--retry", "3", "https://example.test/payload.sh"},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return api.Event{EventID: "evt-1", HostID: "host-1", EventType: "exec", Payload: payload, TimestampNs: 1}
}

// BenchmarkNewEventExec measures what one Sigma-backed rule pays to look at one exec event.
//
// This is the cost issue #794 is about, and the number only matters when multiplied: the engine hands every rule the raw batch, so
// each rule that wants Sigma fields builds its own adapter and pays this again for the same event. Recording it as a benchmark
// rather than as a figure in a PR description is the point, since the figure is what a later change would silently undo.
func BenchmarkNewEventExec(b *testing.B) {
	evt := benchExecEvent(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		e, err := NewEvent(evt)
		if err != nil {
			b.Fatal(err)
		}
		// Read a field so the compiler cannot decide the construction is dead.
		if _, ok := e.Field("CommandLine"); !ok {
			b.Fatal("CommandLine absent")
		}
	}
}
