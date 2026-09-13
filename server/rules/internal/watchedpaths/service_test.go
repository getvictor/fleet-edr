package watchedpaths

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestReplaceResult_JSONRoundTrip pins the PUT response shape, including the skip reason, which is omitted when empty.
func TestReplaceResult_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := ReplaceResult{
			Set:                 api.WatchedPathSet{Version: rapid.Int64().Draw(t, "version"), Paths: []api.WatchedPath{}},
			FanoutHosts:         rapid.Int().Draw(t, "hosts"),
			FanoutFailed:        rapid.Int().Draw(t, "failed"),
			FanoutSkippedReason: rapid.SampledFrom([]string{"", "host_lister_error"}).Draw(t, "reason"),
		}
		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got ReplaceResult
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, want, got)
		if want.FanoutSkippedReason == "" {
			assert.NotContains(t, string(b), "fanout_skipped_reason")
		}
	})
}
