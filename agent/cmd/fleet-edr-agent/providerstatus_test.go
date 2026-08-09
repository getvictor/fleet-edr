package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseProviderStatus pins the filter that keeps the network extension's liveness control message out of the upload queue
// while letting every ordinary event through untouched (issue #649).
//
// spec:agent-status-reporting/capture-provider-status-is-a-control-message-not-telemetry/a-provider-status-message-is-not-uploaded
// spec:agent-status-reporting/capture-provider-status-is-a-control-message-not-telemetry/ordinary-telemetry-is-unaffected-by-the-filter
func TestParseProviderStatus(t *testing.T) {
	t.Parallel()
	t.Run("recognises a status message and returns its providers", func(t *testing.T) {
		t.Parallel()
		status, ok := parseProviderStatus([]byte(`{
			"event_id":"e1","host_id":"h1","timestamp_ns":1,"platform":"darwin",
			"event_type":"ne_provider_status",
			"payload":{"providers":{"content_filter":"running","dns_proxy":"stopped"}}
		}`))
		require.True(t, ok)
		assert.Equal(t, map[string]string{"content_filter": "running", "dns_proxy": "stopped"}, status.Providers)
	})

	t.Run("an empty provider set is a status message, not a miss", func(t *testing.T) {
		t.Parallel()
		// This is the #649 signal itself: the extension is up and NOTHING started. Treating it as "not a status message"
		// would drop the one report that matters and leave health stuck at awaiting.
		status, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{}}}`))
		require.True(t, ok)
		assert.Empty(t, status.Providers)
	})

	t.Run("a missing providers map still reports as a status message", func(t *testing.T) {
		t.Parallel()
		status, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{}}`))
		require.True(t, ok)
		assert.NotNil(t, status.Providers, "a nil map would be indistinguishable from a parse miss at the call site")
		assert.Empty(t, status.Providers)
	})

	t.Run("ordinary telemetry is left alone", func(t *testing.T) {
		t.Parallel()
		// Every real event takes this path, so a false positive here would silently drop telemetry.
		for _, body := range []string{
			`{"event_type":"exec","payload":{"pid":1}}`,
			`{"event_type":"dns_query","payload":{"query_name":"example.com"}}`,
			`{"event_type":"network_connect","payload":{}}`,
		} {
			status, ok := parseProviderStatus([]byte(body))
			assert.False(t, ok, body)
			assert.Nil(t, status.Providers)
		}
	})

	t.Run("malformed or empty input is not a status message", func(t *testing.T) {
		t.Parallel()
		for _, body := range []string{``, `not json`, `{`, `[]`, `null`} {
			status, ok := parseProviderStatus([]byte(body))
			assert.False(t, ok, body)
			assert.Nil(t, status.Providers)
		}
	})

	t.Run("a stopped provider carries its raw stop reason", func(t *testing.T) {
		t.Parallel()
		// The reason is what lets a detection consumer tell an operator-driven stop from an upgrade. A regression that
		// mangles it while provider states still decode would pass every other case in this table.
		status, ok := parseProviderStatus([]byte(`{
			"event_type":"ne_provider_status",
			"payload":{"providers":{"content_filter":"stopped"},"stop_reasons":{"content_filter":1}}
		}`))
		require.True(t, ok)
		assert.Equal(t, map[string]string{"content_filter": "stopped"}, status.Providers)
		assert.Equal(t, map[string]int{"content_filter": 1}, status.StopReasons)
		assert.True(t, status.Decoded)
	})

	t.Run("an extension that sends no stop_reasons still decodes", func(t *testing.T) {
		t.Parallel()
		// Version skew across an upgrade. The states are the load-bearing part; the reasons are additive.
		status, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{"dns_proxy":"running"}}}`))
		require.True(t, ok)
		assert.Equal(t, map[string]string{"dns_proxy": "running"}, status.Providers)
		assert.Nil(t, status.StopReasons)
		assert.True(t, status.Decoded)
	})

	t.Run("an undecodable payload is a control message but NOT a usable report", func(t *testing.T) {
		t.Parallel()
		// Both an undecodable payload and a genuine "nothing is running" report yield an empty map, and health treats them
		// alike. Transition recording must not: feeding an undecodable report to the recorder would clear its baseline and
		// make the next valid report look like a fresh set of transitions, inventing tamper evidence from a parse error.
		status, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{"providers":"not-a-map"}}`))
		require.True(t, ok, "still a control message, so it must stay out of the upload queue")
		assert.Empty(t, status.Providers)
		assert.False(t, status.Decoded, "an unreadable report must not be used as a transition baseline")
	})

	t.Run("an explicitly empty provider set IS a usable report", func(t *testing.T) {
		t.Parallel()
		// The #649 signal itself: the extension is up and nothing started. Distinct from an unreadable payload.
		status, ok := parseProviderStatus([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{}}}`))
		require.True(t, ok)
		assert.Empty(t, status.Providers)
		assert.True(t, status.Decoded, "an explicit empty map is information, not a parse failure")
	})
}

// FuzzParseProviderStatus drives the parser with arbitrary bytes. It decodes untrusted input off the XPC event channel, which the
// testing-strategy matrix puts squarely in the fuzz column, and the two invariants asserted here are the ones the call site in
// startReceiverLoop actually depends on:
//
//   - `ok` is true for exactly those inputs that really are provider-status envelopes. A false positive silently DROPS a
//     telemetry event (the receiver loop returns early), which is the expensive direction of this bug and is invisible at runtime.
//   - a recognised message never yields a nil map, so the caller can hand it straight to GradeProviders without a nil check.
func FuzzParseProviderStatus(f *testing.F) {
	f.Add([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{"content_filter":"running"}}}`))
	f.Add([]byte(`{"event_type":"ne_provider_status","payload":{"providers":{}}}`))
	f.Add([]byte(`{"event_type":"ne_provider_status","payload":{}}`))
	f.Add([]byte(`{"event_type":"ne_provider_status"}`))
	f.Add([]byte(`{"event_type":"exec","payload":{"pid":1}}`))
	f.Add([]byte(`{"event_type":"ne_provider_status","payload":{"providers":null}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	// Found by this fuzzer on first run. encoding/json matches struct tags case-insensitively, so a case-variant KEY still
	// decodes; only the VALUE comparison is exact. Kept as a seed because it pins that behaviour deliberately: every other
	// event_type decode in the agent (eventHeader, reconcile, the Windows mapper) is a plain struct-tag decode with the same
	// semantics, so tightening this one parser alone would make it the odd one out rather than make the agent safer.
	f.Add([]byte(`{"event_tYpe":"ne_provider_status","payload":{}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		status, ok := parseProviderStatus(data)

		// Independent oracle: decode into a generic map and ask only "does some key that encoding/json would bind to
		// event_type carry the control value". Written against the decoder's real semantics rather than the
		// implementation's own peek, so a regression that widens the match on the VALUE side shows up as a disagreement.
		var oracle map[string]json.RawMessage
		wantOK := false
		if json.Unmarshal(data, &oracle) == nil {
			for key, raw := range oracle {
				if !strings.EqualFold(key, "event_type") {
					continue
				}
				var eventType string
				if json.Unmarshal(raw, &eventType) == nil && eventType == providerStatusEventType {
					wantOK = true
					break
				}
			}
		}
		require.Equal(t, wantOK, ok, "drop decision disagrees with the event_type actually present in %q", data)

		if ok {
			require.NotNil(t, status.Providers, "a recognised status message must never yield a nil map")
		} else {
			require.Nil(t, status.Providers)
		}
	})
}
