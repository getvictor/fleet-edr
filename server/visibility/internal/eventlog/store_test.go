package eventlog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/visibility/api"
)

func TestNew_NilDB(t *testing.T) {
	t.Parallel()
	_, err := New(nil)
	require.Error(t, err)
}

func TestAppendArgs(t *testing.T) {
	t.Parallel()
	events := []api.Event{
		{EventID: "e1", HostID: "h1", TimestampNs: 10, IngestedAtNs: 11, EventType: "exec", Payload: json.RawMessage(`{"pid":1}`)},
		{EventID: "e2", HostID: "h1", TimestampNs: 20, IngestedAtNs: 21, EventType: "fork", Payload: json.RawMessage(`{"pid":2}`)},
	}
	placeholders, args, err := appendArgs(events)
	require.NoError(t, err)
	assert.Equal(t, []string{"(?, ?, ?, ?, ?, ?)", "(?, ?, ?, ?, ?, ?)"}, placeholders)
	require.Len(t, args, 12)
	// First row's flattened args, in column order.
	assert.Equal(t, "e1", args[0])
	assert.Equal(t, "h1", args[1])
	assert.Equal(t, int64(10), args[2])
	assert.Equal(t, int64(11), args[3])
	assert.Equal(t, "exec", args[4])
	assert.Equal(t, []byte(`{"pid":1}`), args[5])
}
