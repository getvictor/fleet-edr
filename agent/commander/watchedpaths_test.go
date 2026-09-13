package commander

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// runWatchedPaths executes one set_watched_paths command and returns the terminal status and decoded result.
func runWatchedPaths(t *testing.T, sender ExtensionSender, payload string) (string, map[string]any) {
	t.Helper()
	var status string
	var result json.RawMessage
	report := func(_ context.Context, s string, r json.RawMessage) error {
		status, result = s, r
		return nil
	}
	cmd := Command{ID: 1, CommandType: "set_watched_paths", Payload: json.RawMessage(payload)}
	NewExecutor(sender, nil, nil).Execute(t.Context(), cmd, report)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(result, &decoded))
	return status, decoded
}

// spec:agent-command-executor/set-watched-paths-command/watched-paths-forwarded-successfully
func TestExecuteSetWatchedPaths_ForwardsTheRawPayload(t *testing.T) {
	t.Parallel()
	sender := &recordingExtensionSender{}
	raw := `{"version":5,"epoch":1789300000000000,"paths":[{"path":"/Library/StartupItems/","match":"prefix"},{"path":"/etc/emond.d/","match":"prefix"}]}`

	status, result := runWatchedPaths(t, sender, raw)

	assert.Equal(t, StatusCompleted, status)
	require.Len(t, sender.watched, 1)
	// Byte equality: the extension decodes what the server wrote, not a re-marshalled copy.
	assert.Equal(t, []byte(raw), sender.watched[0])
	assert.Empty(t, sender.sent, "a watched-path set is not an application-control snapshot")
	assert.Equal(t, map[string]any{"version": float64(5), "paths": float64(2)}, result)
}

// The agent does not read epoch, so an epoch the extension would reject still reaches it byte for byte; judging it is the extension's job.
func TestExecuteSetWatchedPaths_ForwardsAnEpochItDoesNotRead(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"version":3,"epoch":"not a number","paths":[]}`,
		`{"version":3,"epoch":1.5,"paths":[]}`,
		`{"version":3,"epoch":null,"paths":[]}`,
	} {
		sender := &recordingExtensionSender{}
		status, _ := runWatchedPaths(t, sender, raw)
		assert.Equal(t, StatusCompleted, status, raw)
		require.Len(t, sender.watched, 1)
		assert.Equal(t, []byte(raw), sender.watched[0])
	}
}

// An empty set is how the server removes every path it added; the extension keeps its built-in paths regardless.
func TestExecuteSetWatchedPaths_ForwardsAnEmptySet(t *testing.T) {
	t.Parallel()
	sender := &recordingExtensionSender{}

	status, result := runWatchedPaths(t, sender, `{"version":6,"paths":[]}`)

	assert.Equal(t, StatusCompleted, status)
	assert.Len(t, sender.watched, 1)
	assert.EqualValues(t, 0, result["paths"])
}

// spec:agent-command-executor/set-watched-paths-command/a-watched-path-payload-is-invalid
func TestExecuteSetWatchedPaths_RejectsAnInvalidEnvelope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		payload string
		reason  string
	}{
		{"malformed json", `{`, "invalid payload"},
		{"missing version", `{"paths":[]}`, "version"},
		{"zero version", `{"version":0,"paths":[]}`, "version"},
		{"negative version", `{"version":-1,"paths":[]}`, "version"},
		{"missing paths", `{"version":1}`, "paths"},
		{"null paths", `{"version":1,"paths":null}`, "paths"},
		{"paths is an object", `{"version":1,"paths":{}}`, "paths"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sender := &recordingExtensionSender{}

			status, result := runWatchedPaths(t, sender, tc.payload)

			assert.Equal(t, StatusFailed, status)
			assert.Contains(t, result["error"], tc.reason)
			assert.Empty(t, sender.watched, "an invalid envelope must not reach the extension")
		})
	}
}

// spec:agent-command-executor/set-watched-paths-command/the-watched-path-set-cannot-reach-the-extension
func TestExecuteSetWatchedPaths_ReportsWhyItCouldNotForward(t *testing.T) {
	t.Parallel()
	valid := `{"version":1,"paths":[]}`

	t.Run("no bridge", func(t *testing.T) {
		t.Parallel()
		status, result := runWatchedPaths(t, nil, valid)
		assert.Equal(t, StatusFailed, status)
		assert.Equal(t, "extension sender not configured", result["error"])
	})

	t.Run("transport refuses", func(t *testing.T) {
		t.Parallel()
		status, result := runWatchedPaths(t, &recordingExtensionSender{sendErr: errors.New("receiver not connected")}, valid)
		assert.Equal(t, StatusFailed, status)
		assert.Equal(t, "xpc send: receiver not connected", result["error"])
	})
}

// TestSetWatchedPathsPayload_JSONRoundTrip is the Marshal-then-Unmarshal identity check the repo asks of a new wire shape. The entries
// stay raw here, so what it pins is that the envelope's version survives and its paths come back byte for byte.
func TestSetWatchedPathsPayload_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		entries := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) map[string]string {
			return map[string]string{
				"path":  "/" + rapid.StringMatching(`[A-Za-z0-9._/ -]{0,40}`).Draw(t, "path"),
				"match": rapid.SampledFrom([]string{"literal", "prefix"}).Draw(t, "match"),
			}
		}), 0, 8).Draw(t, "entries")
		paths, err := json.Marshal(entries)
		require.NoError(t, err)
		want := setWatchedPathsPayload{Version: rapid.Int64().Draw(t, "version"), Paths: paths}

		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got setWatchedPathsPayload
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, want, got)
	})
}

// FuzzRunSetWatchedPaths feeds arbitrary payloads through the handler. Whatever arrives, it must not panic, and it may report completed
// only for an envelope with a positive version and a paths array, having forwarded exactly the bytes it received.
func FuzzRunSetWatchedPaths(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"paths":[]}`,
		`{"version":2,"epoch":5,"paths":[{"path":"/Library/StartupItems/","match":"prefix"}]}`,
		`{"version":0,"paths":[]}`,
		`{"version":1,"paths":{}}`,
		`{`,
		`null`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		sender := &recordingExtensionSender{}
		status, result := NewExecutor(sender, nil, nil).run(t.Context(),
			Command{ID: 1, CommandType: "set_watched_paths", Payload: json.RawMessage(payload)})
		if status != StatusCompleted {
			assert.Empty(t, sender.watched, "a payload that failed must not reach the extension")
			return
		}
		var envelope setWatchedPathsPayload
		require.NoError(t, json.Unmarshal([]byte(payload), &envelope))
		assert.Positive(t, envelope.Version)
		assert.True(t, isJSONArray(envelope.Paths))
		require.Len(t, sender.watched, 1)
		assert.Equal(t, []byte(payload), sender.watched[0])
		assert.NotEmpty(t, result)
	})
}
