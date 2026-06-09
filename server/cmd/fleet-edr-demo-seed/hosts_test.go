package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/fakeagent"
)

// TestLoadHostEnvelopes_EachManifestHost confirms every embedded host corpus parses, carries a single host_id, and is scrubbed:
// no snapshot_heartbeat (dropped by the scrub) and the three telemetry streams (exec, network_connect, dns_query) are present, so
// a replayed host actually shows the deep-tree + correlated-DNS data the demo promises.
func TestLoadHostEnvelopes_EachManifestHost(t *testing.T) {
	t.Parallel()
	for _, host := range hostManifest {
		t.Run(host.File, func(t *testing.T) {
			t.Parallel()
			envs, hostID, err := loadHostEnvelopes(host.File)
			require.NoError(t, err)
			require.NotEmpty(t, envs)
			assert.NotEmpty(t, hostID)

			types := map[string]int{}
			for _, e := range envs {
				assert.Equal(t, hostID, e.HostID, "every envelope shares the host's UUID")
				types[e.EventType]++
			}
			assert.Zero(t, types["snapshot_heartbeat"], "scrub must drop snapshot_heartbeat noise")
			for _, want := range []string{"exec", "network_connect", "dns_query"} {
				assert.Positive(t, types[want], "captured host must carry %s events", want)
			}
		})
	}
}

func TestShiftEnvelopesToRecent(t *testing.T) {
	t.Parallel()

	t.Run("empty input is returned unchanged", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, shiftEnvelopesToRecent(nil, time.Now()))
	})

	t.Run("latest event lands at now-recentTailOffset and deltas are preserved", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_900_000_000, 0)
		envs := []fakeagent.Envelope{
			{TimestampNs: 1000},
			{TimestampNs: 4000}, // latest
			{TimestampNs: 2500},
		}
		shiftEnvelopesToRecent(envs, now)

		wantLatest := now.Add(-recentTailOffset).UnixNano()
		assert.Equal(t, wantLatest, envs[1].TimestampNs, "latest event pinned to now-offset")
		// Inter-event deltas from the original capture are preserved exactly.
		assert.Equal(t, int64(4000-1000), envs[1].TimestampNs-envs[0].TimestampNs)
		assert.Equal(t, int64(4000-2500), envs[1].TimestampNs-envs[2].TimestampNs)
		// Every event is in the past (never future-dated).
		assert.Less(t, envs[1].TimestampNs, now.UnixNano())
	})
}
