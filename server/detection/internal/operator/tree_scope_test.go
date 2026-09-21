package operator

import (
	"context"
	"net/http"
	"testing"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ?scope=chain reads the pinned process with its ancestors and descendants instead of the host's window, which is the difference
// between a read costing the chain and one costing however busy the host was (issue #1138). The routing is asserted here because it
// is a wire contract: the parameter has to reach the right read, and a page asking for a chain and silently getting the window is
// exactly the failure this replaces.
func TestProcessTreeHandler_scopeChainRoutesToTheChainRead(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		query     string
		wantChain bool
	}{
		{name: "scope=chain with a pin reads the chain", query: "?scope=chain&pin=42", wantChain: true},
		{name: "no scope reads the window", query: "?pin=42", wantChain: false},
		{name: "another scope reads the window", query: "?scope=host&pin=42", wantChain: false},
		// A chain needs a process to be the chain OF. Asked for one without naming a process, the honest read is the host's, not an
		// error: the caller has described the host.
		{name: "scope=chain without a pin reads the window", query: "?scope=chain", wantChain: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var tookChain, tookWindow bool
			svc := fakeService{
				buildTree: func(context.Context, string, api.TimeRange, int, bool, int64) (api.ProcessTreeResult, error) {
					tookWindow = true
					return api.ProcessTreeResult{}, nil
				},
				buildChainTree: func(context.Context, string, api.TimeRange, int64, bool) (api.ProcessTreeResult, error) {
					tookChain = true
					return api.ProcessTreeResult{}, nil
				},
			}
			srv := newOperatorServer(t, svc, allowAllAuthZ{})
			resp := doGet(t, srv, "/api/hosts/host-a/tree"+tc.query)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			assert.Equal(t, tc.wantChain, tookChain, "chain read")
			assert.Equal(t, !tc.wantChain, tookWindow, "window read")
		})
	}
}

// The pinned id reaches the chain read as the process to read the chain of.
func TestProcessTreeHandler_scopeChainPassesThePinnedProcess(t *testing.T) {
	t.Parallel()
	var got int64
	svc := fakeService{
		buildChainTree: func(_ context.Context, _ string, _ api.TimeRange, pinnedID int64, _ bool) (api.ProcessTreeResult, error) {
			got = pinnedID
			return api.ProcessTreeResult{}, nil
		},
	}
	srv := newOperatorServer(t, svc, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/host-a/tree?scope=chain&pin=875325")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int64(875325), got)
}
