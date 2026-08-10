package eventid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewV4FormatAndUniqueness pins the format the server and schema/events.json both depend on. Moved here from
// agent/reconcile when the helper was shared with agent/sensorevent, so the contract is tested once where it lives rather
// than in one of the two callers.
func TestNewV4FormatAndUniqueness(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for range 500 {
		u, err := NewV4()
		require.NoError(t, err)
		require.Len(t, u, 36)
		assert.Equal(t, byte('-'), u[8])
		assert.Equal(t, byte('-'), u[13])
		assert.Equal(t, byte('-'), u[18])
		assert.Equal(t, byte('-'), u[23])
		assert.Equal(t, byte('4'), u[14], "version nibble must be 4")
		assert.Contains(t, "89ab", string(u[19]), "variant nibble must be 8/9/a/b")
		// A duplicate would be silently deduped away by the server, losing the event rather than failing loudly.
		assert.False(t, seen[u], "uuids must be unique across calls")
		seen[u] = true
	}
}
