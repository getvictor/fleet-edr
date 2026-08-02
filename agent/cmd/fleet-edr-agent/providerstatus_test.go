package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseProviderStatus pins the filter that keeps the network extension's liveness control message out of the upload queue
// while letting every ordinary event through untouched (issue #649).
func TestParseProviderStatus(t *testing.T) {
	t.Parallel()
	t.Run("recognises a status message and returns its providers", func(t *testing.T) {
		t.Parallel()
		providers, ok := parseProviderStatus([]byte(`{
			"event_id":"e1","host_id":"h1","timestamp_ns":1,"platform":"darwin",
			"event_type":"ne_provider_status",
			"payload":{"providers":{"content_filter":"running","dns_proxy":"stopped"}}
		}`))
		require.True(t, ok)
		assert.Equal(t, map[string]string{"content_filter": "running", "dns_proxy": "stopped"}, providers)
	})

	t.Run("an empty provider set is a status message, not a miss", func(t *testing.T) {
		t.Parallel()
		// This is the #649 signal itself: the extension is up and NOTHING started. Treating it as "not a status message"
		// would drop the one report that matters and leave health stuck at awaiting.
		providers, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{}}}`))
		require.True(t, ok)
		assert.Empty(t, providers)
	})

	t.Run("a missing providers map still reports as a status message", func(t *testing.T) {
		t.Parallel()
		providers, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{}}`))
		require.True(t, ok)
		assert.NotNil(t, providers, "a nil map would be indistinguishable from a parse miss at the call site")
		assert.Empty(t, providers)
	})

	t.Run("ordinary telemetry is left alone", func(t *testing.T) {
		t.Parallel()
		// Every real event takes this path, so a false positive here would silently drop telemetry.
		for _, body := range []string{
			`{"event_type":"exec","payload":{"pid":1}}`,
			`{"event_type":"dns_query","payload":{"query_name":"example.com"}}`,
			`{"event_type":"network_connect","payload":{}}`,
		} {
			providers, ok := parseProviderStatus([]byte(body))
			assert.False(t, ok, body)
			assert.Nil(t, providers)
		}
	})

	t.Run("malformed or empty input is not a status message", func(t *testing.T) {
		t.Parallel()
		for _, body := range []string{``, `not json`, `{`, `[]`, `null`} {
			providers, ok := parseProviderStatus([]byte(body))
			assert.False(t, ok, body)
			assert.Nil(t, providers)
		}
	})
}
