package operator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

type fakeProcessSearch struct {
	fn func(ctx context.Context, filter api.ProcessSearchFilter, cursor string, limit int) (api.ProcessSearchResult, error)
}

func (f fakeProcessSearch) SearchProcesses(ctx context.Context, filter api.ProcessSearchFilter, cursor string, limit int) (api.ProcessSearchResult, error) {
	return f.fn(ctx, filter, cursor, limit)
}

func newSearchServer(t *testing.T, sr ProcessSearchReader, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if sr != nil {
		h.SetProcessSearch(sr)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// spec:server-rest-api/fleet-wide-process-search-endpoint/filters-compose-across-hosts
func TestHandleProcessSearch_ParsesFiltersAndReturnsResult(t *testing.T) {
	t.Parallel()
	var got api.ProcessSearchFilter
	var gotLimit int
	sr := fakeProcessSearch{fn: func(_ context.Context, filter api.ProcessSearchFilter, _ string, limit int) (api.ProcessSearchResult, error) {
		got, gotLimit = filter, limit
		return api.ProcessSearchResult{
			Rows:         []api.Process{{ID: 1, HostID: "h1", PID: 42, Path: "/bin/zsh"}},
			NextCursor:   "abc",
			TotalMatched: 7,
		}, nil
	}}
	srv := newSearchServer(t, sr, allowAllAuthZ{})

	uid := "0"
	resp := doGet(t, srv, "/api/search/processes?"+url.Values{
		"signing":     {"unsigned"},
		"uid":         {uid},
		"path":        {"grep"},
		"hash":        {"abc123"},
		"host_id":     {"h1"},
		"exit_reason": {"reexec"},
		"from":        {"100"},
		"to":          {"200"},
		"limit":       {"25"},
	}.Encode())
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "unsigned", got.Signing)
	require.NotNil(t, got.UID)
	assert.Equal(t, 0, *got.UID)
	assert.Equal(t, "grep", got.Path)
	assert.Equal(t, "abc123", got.Hash)
	assert.Equal(t, "h1", got.HostID)
	assert.Equal(t, "reexec", got.ExitReason)
	assert.EqualValues(t, 100, got.FromNs)
	assert.EqualValues(t, 200, got.ToNs)
	assert.Equal(t, 25, gotLimit)

	var out api.ProcessSearchResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.EqualValues(t, 7, out.TotalMatched)
	assert.Equal(t, "abc", out.NextCursor)
	require.Len(t, out.Rows, 1)
}

func TestHandleProcessSearch_ClampsLimit(t *testing.T) {
	t.Parallel()
	var gotLimit int
	sr := fakeProcessSearch{fn: func(_ context.Context, _ api.ProcessSearchFilter, _ string, limit int) (api.ProcessSearchResult, error) {
		gotLimit = limit
		return api.ProcessSearchResult{}, nil
	}}
	srv := newSearchServer(t, sr, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/processes?limit=99999")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, searchMaxLimit, gotLimit, "an oversized limit is clamped to the max page")
}

// spec:server-rest-api/fleet-wide-process-search-endpoint/malformed-cursor-is-rejected
func TestHandleProcessSearch_MalformedCursorIs400(t *testing.T) {
	t.Parallel()
	sr := fakeProcessSearch{fn: func(context.Context, api.ProcessSearchFilter, string, int) (api.ProcessSearchResult, error) {
		return api.ProcessSearchResult{}, api.ErrInvalidCursor
	}}
	srv := newSearchServer(t, sr, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/processes?cursor=garbage")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// spec:server-rest-api/fleet-wide-process-search-endpoint/an-out-of-vocabulary-filter-value-is-rejected
func TestHandleProcessSearch_RejectsBadInput(t *testing.T) {
	t.Parallel()
	sr := fakeProcessSearch{fn: func(context.Context, api.ProcessSearchFilter, string, int) (api.ProcessSearchResult, error) {
		t.Fatal("reader must not be reached for a rejected request")
		return api.ProcessSearchResult{}, nil
	}}
	srv := newSearchServer(t, sr, allowAllAuthZ{})

	cases := []struct{ name, query string }{
		{"unknown signing class", "?signing=notarized"},
		{"misspelled signing class", "?signing=platfor" + "m_typo"},
		{"unknown exit reason", "?exit_reason=terminated"},
		{"misspelled exit reason", "?exit_reason=pid_reused"},
		{"unparseable from", "?from=abc"},
		{"negative from", "?from=-100"},
		{"unparseable to", "?to=notanumber"},
		{"negative uid", "?uid=-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := doGet(t, srv, "/api/search/processes"+tc.query)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestHandleProcessSearch_InvalidUidIs400(t *testing.T) {
	t.Parallel()
	sr := fakeProcessSearch{fn: func(context.Context, api.ProcessSearchFilter, string, int) (api.ProcessSearchResult, error) {
		t.Fatal("reader must not be reached for an unparseable uid")
		return api.ProcessSearchResult{}, nil
	}}
	srv := newSearchServer(t, sr, allowAllAuthZ{})

	resp := doGet(t, srv, "/api/search/processes?uid=notanumber")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleProcessSearch_UnwiredIs503(t *testing.T) {
	t.Parallel()
	srv := newSearchServer(t, nil, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/search/processes")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandleProcessSearch_DeniedByAuthz(t *testing.T) {
	t.Parallel()
	sr := fakeProcessSearch{fn: func(context.Context, api.ProcessSearchFilter, string, int) (api.ProcessSearchResult, error) {
		t.Fatal("reader must not be reached when authz denies")
		return api.ProcessSearchResult{}, nil
	}}
	srv := newSearchServer(t, sr, denyAllAuthZ{})
	resp := doGet(t, srv, "/api/search/processes")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
