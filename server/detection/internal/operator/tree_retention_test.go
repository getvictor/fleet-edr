package operator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

func treeWithRetention(t *testing.T, days int) map[string]json.RawMessage {
	t.Helper()
	svc := fakeService{
		buildTree: func(context.Context, string, api.TimeRange, int, bool, int64) (api.ProcessTreeResult, error) {
			return api.ProcessTreeResult{}, nil
		},
	}
	h := New(svc, allowAllAuthZ{}, slog.Default())
	h.SetProcessRetention(days)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp := doGet(t, srv, "/api/hosts/host-a/tree")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

// spec:server-rest-api/the-graph-says-where-retained-process-records-begin/a-window-past-retention-is-told-where-records-begin
//
// A window that reaches back past process retention can return a lone alerted process with none of its neighbours (issue #1153),
// and the read is not truncated, so the response itself must carry where the retained records begin.
func TestProcessTree_SaysWhereRetainedRecordsBegin(t *testing.T) {
	t.Parallel()
	before := time.Now()
	body := treeWithRetention(t, 7)

	raw, ok := body["retained_from_ns"]
	require.True(t, ok, "a deployment that prunes process records says from when it keeps them")
	var from int64
	require.NoError(t, json.Unmarshal(raw, &from))
	want := before.Add(-7 * 24 * time.Hour).UnixNano()
	assert.InDelta(t, want, from, float64(time.Minute), "seven days before now")
}

// spec:server-rest-api/the-graph-says-where-retained-process-records-begin/no-boundary-when-retention-is-disabled
func TestProcessTree_NoBoundaryWhenRetentionIsDisabled(t *testing.T) {
	t.Parallel()
	for _, days := range []int{0, -1} {
		body := treeWithRetention(t, days)
		_, ok := body["retained_from_ns"]
		assert.Falsef(t, ok, "retention %d keeps everything, so there is no boundary to report", days)
	}
}
