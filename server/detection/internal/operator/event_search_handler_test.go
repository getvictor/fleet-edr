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

	identityapi "github.com/fleetdm/edr/server/identity/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

type fakeEventSearch struct {
	fn func(ctx context.Context, filter visibilityapi.EventSearchFilter, cursor string, limit int) (visibilityapi.EventSearchResult, error)
}

func (f fakeEventSearch) SearchEvents(ctx context.Context, filter visibilityapi.EventSearchFilter, cursor string, limit int) (visibilityapi.EventSearchResult, error) {
	return f.fn(ctx, filter, cursor, limit)
}

func newEventSearchServer(t *testing.T, er EventSearchReader, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if er != nil {
		h.SetEventSearch(er)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/connection-search-finds-a-remote-address-across-hosts
func TestHandleConnectionSearch_MapsToRemoteAddress(t *testing.T) {
	t.Parallel()
	var got visibilityapi.EventSearchFilter
	er := fakeEventSearch{fn: func(_ context.Context, f visibilityapi.EventSearchFilter, _ string, limit int) (visibilityapi.EventSearchResult, error) {
		got = f
		return visibilityapi.EventSearchResult{
			Events:       []visibilityapi.Event{{EventID: "e1", HostID: "h1", EventType: "network_connect"}},
			TotalMatched: 3,
		}, nil
	}}
	srv := newEventSearchServer(t, er, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/connections?remote_address=203.0.113.7&host_id=h1&from=100&to=200")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "network_connect", got.EventType)
	assert.Equal(t, "203.0.113.7", got.Value)
	assert.Equal(t, "h1", got.HostID)
	assert.EqualValues(t, 100, got.FromNs)
	assert.EqualValues(t, 200, got.ToNs)
	var out visibilityapi.EventSearchResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.EqualValues(t, 3, out.TotalMatched)
	require.Len(t, out.Events, 1)
}

// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/dns-search-finds-a-query-name-across-hosts
func TestHandleDNSSearch_MapsToQueryName(t *testing.T) {
	t.Parallel()
	var got visibilityapi.EventSearchFilter
	er := fakeEventSearch{fn: func(_ context.Context, f visibilityapi.EventSearchFilter, _ string, _ int) (visibilityapi.EventSearchResult, error) {
		got = f
		return visibilityapi.EventSearchResult{}, nil
	}}
	srv := newEventSearchServer(t, er, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/dns?query_name=evil.example")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "dns_query", got.EventType)
	assert.Equal(t, "evil.example", got.Value)
}

// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/absent-artifact-value-lists-recent-events
func TestHandleEventSearch_NoValueListsRecentEvents(t *testing.T) {
	t.Parallel()
	var got visibilityapi.EventSearchFilter
	reached := 0
	er := fakeEventSearch{fn: func(_ context.Context, f visibilityapi.EventSearchFilter, _ string, _ int) (visibilityapi.EventSearchResult, error) {
		got = f
		reached++
		return visibilityapi.EventSearchResult{
			Events:       []visibilityapi.Event{{EventID: "recent", HostID: "h1", EventType: f.EventType}},
			TotalMatched: 1,
		}, nil
	}}
	srv := newEventSearchServer(t, er, allowAllAuthZ{})

	// An absent (or empty) artifact value lists recent events of the type instead of 400ing; the reader is reached with no Value filter.
	for _, path := range []string{"/api/search/connections", "/api/search/dns?query_name="} {
		resp := doGet(t, srv, path)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "path %q", path)
		resp.Body.Close()
	}
	assert.Equal(t, 2, reached, "both routes queried the reader")
	assert.Empty(t, got.Value, "no artifact filter is applied when the value is absent")
}

func TestHandleEventSearch_MalformedCursorIs400(t *testing.T) {
	t.Parallel()
	er := fakeEventSearch{fn: func(context.Context, visibilityapi.EventSearchFilter, string, int) (visibilityapi.EventSearchResult, error) {
		return visibilityapi.EventSearchResult{}, visibilityapi.ErrInvalidEventCursor
	}}
	srv := newEventSearchServer(t, er, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/connections?remote_address=1.2.3.4&cursor=garbage")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleEventSearch_BadWindowIs400(t *testing.T) {
	t.Parallel()
	er := fakeEventSearch{fn: func(context.Context, visibilityapi.EventSearchFilter, string, int) (visibilityapi.EventSearchResult, error) {
		t.Fatal("reader must not be reached for a bad window")
		return visibilityapi.EventSearchResult{}, nil
	}}
	srv := newEventSearchServer(t, er, allowAllAuthZ{})

	for _, query := range []string{"?remote_address=1.2.3.4&from=-5", "?remote_address=1.2.3.4&from=200&to=100"} {
		resp := doGet(t, srv, "/api/search/connections"+query)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "query %q", query)
		resp.Body.Close()
	}
}

func TestHandleEventSearch_UnwiredIs503(t *testing.T) {
	t.Parallel()
	srv := newEventSearchServer(t, nil, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/search/connections?remote_address=1.2.3.4")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleEventSearch_DeniedByAuthz(t *testing.T) {
	t.Parallel()
	er := fakeEventSearch{fn: func(context.Context, visibilityapi.EventSearchFilter, string, int) (visibilityapi.EventSearchResult, error) {
		t.Fatal("reader must not be reached when authz denies")
		return visibilityapi.EventSearchResult{}, nil
	}}
	srv := newEventSearchServer(t, er, denyAllAuthZ{})
	resp := doGet(t, srv, "/api/search/connections?remote_address=1.2.3.4")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
