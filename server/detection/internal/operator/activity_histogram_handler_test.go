package operator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

type fakeHistogram struct {
	fn func(ctx context.Context, hostID string, fromNs, toNs int64) (api.ActivityHistogram, error)
}

func (f fakeHistogram) ActivityHistogram(ctx context.Context, hostID string, fromNs, toNs int64) (api.ActivityHistogram, error) {
	return f.fn(ctx, hostID, fromNs, toNs)
}

func newHistogramServer(t *testing.T, hr ActivityHistogramReader, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if hr != nil {
		h.SetActivityHistogram(hr)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHandleActivityHistogram_Success(t *testing.T) {
	t.Parallel()
	var gotFrom, gotTo int64
	hr := fakeHistogram{fn: func(_ context.Context, _ string, fromNs, toNs int64) (api.ActivityHistogram, error) {
		gotFrom, gotTo = fromNs, toNs
		return api.ActivityHistogram{BucketNs: 60_000_000_000, Total: 5, Buckets: []api.ActivityBucket{{StartNs: 0, Count: 5}}}, nil
	}}
	srv := newHistogramServer(t, hr, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/hosts/host-a/activity-histogram?from=1&to=3600000000000")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.EqualValues(t, 1, gotFrom)
	assert.EqualValues(t, 3_600_000_000_000, gotTo)
	var got api.ActivityHistogram
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.EqualValues(t, 60_000_000_000, got.BucketNs)
	assert.EqualValues(t, 5, got.Total)
	require.Len(t, got.Buckets, 1)
}

// spec:server-rest-api/host-activity-histogram-endpoint/invalid-window-is-rejected
func TestHandleActivityHistogram_BadWindow(t *testing.T) {
	t.Parallel()
	srv := newHistogramServer(t, fakeHistogram{fn: func(context.Context, string, int64, int64) (api.ActivityHistogram, error) {
		t.Fatal("reader must not be reached for a bad window")
		return api.ActivityHistogram{}, nil
	}}, allowAllAuthZ{})

	cases := []struct {
		name  string
		query string
	}{
		{"equal from and to", "?from=100&to=100"},
		{"from after to", "?from=200&to=100"},
		{"non-numeric from", "?from=x&to=100"},
		{"missing from", "?to=100"},
		{"non-positive from", "?from=0&to=100"},
		{"negative from", "?from=-5&to=100"},
		{"no window params", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := doGet(t, srv, "/api/hosts/host-a/activity-histogram"+tc.query)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestHandleActivityHistogram_UnwiredIs503(t *testing.T) {
	t.Parallel()
	srv := newHistogramServer(t, nil, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/host-a/activity-histogram?from=1&to=100")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleActivityHistogram_DeniedByAuthz(t *testing.T) {
	t.Parallel()
	srv := newHistogramServer(t, fakeHistogram{fn: func(context.Context, string, int64, int64) (api.ActivityHistogram, error) {
		t.Fatal("reader must not be reached when authz denies")
		return api.ActivityHistogram{}, nil
	}}, denyAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/host-a/activity-histogram?from=1&to=100")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
