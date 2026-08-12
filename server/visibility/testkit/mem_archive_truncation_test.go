package testkit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
	api "github.com/fleetdm/edr/server/visibility/api"
	"github.com/fleetdm/edr/server/visibility/testkit"
)

// TestEventsByTypeForHost_OverflowIsAnErrorNotAShortPage pins the contract that keeps a bounded correlation read from producing a
// false accusation. The sensor-tamper rule decides "capture never came back" from the ABSENCE of a recovery in its window, so a
// silently truncated page would let a host that emitted enough events to bury its own recovery be reported as tampered with. The
// caller cannot tell a missing event from a dropped one, so the read has to say which it was.
func TestEventsByTypeForHost_OverflowIsAnErrorNotAShortPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := testkit.NewMemArchive()

	events := make([]api.Event, 0, testkit.EventsByTypeRowCap+1)
	for i := range testkit.EventsByTypeRowCap + 1 {
		events = append(events, api.Event{
			EventID:      fmt.Sprintf("e%05d", i),
			HostID:       "h1",
			EventType:    "sensor_provider_transition",
			TimestampNs:  int64(i + 1),
			IngestedAtNs: int64(i + 1),
			Payload:      json.RawMessage(`{"provider":"content_filter","state":"stopped"}`),
		})
	}
	require.NoError(t, arch.Insert(ctx, events))

	window := httpserver.TimeRange{FromNs: 0, ToNs: int64(len(events) + 1)}
	got, err := arch.EventsByTypeForHost(ctx, "h1", "sensor_provider_transition", window)
	require.ErrorIs(t, err, api.ErrEventsTruncated, "a result past the cap must be reported, not silently shortened")
	assert.Empty(t, got, "no partial data alongside the error: a caller must not be able to reason from it")

	// One row below the cap is a complete answer and must succeed, so the guard cannot be satisfied by refusing everything.
	narrow := httpserver.TimeRange{FromNs: 0, ToNs: int64(testkit.EventsByTypeRowCap)}
	got, err = arch.EventsByTypeForHost(ctx, "h1", "sensor_provider_transition", narrow)
	require.NoError(t, err)
	assert.Len(t, got, testkit.EventsByTypeRowCap)
}
