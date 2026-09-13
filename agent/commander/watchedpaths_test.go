package commander

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	raw := `{"version":5,"paths":[{"path":"/Library/StartupItems/","match":"prefix"},{"path":"/etc/emond.d/","match":"prefix"}]}`

	status, result := runWatchedPaths(t, sender, raw)

	assert.Equal(t, StatusCompleted, status)
	require.Len(t, sender.watched, 1)
	// Byte equality: the extension decodes what the server wrote, not a re-marshalled copy.
	assert.Equal(t, []byte(raw), sender.watched[0])
	assert.Empty(t, sender.sent, "a watched-path set is not an application-control snapshot")
	assert.Equal(t, map[string]any{"version": float64(5), "paths": float64(2)}, result)
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
