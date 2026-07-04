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
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

// The timeline handler tests drive the real in-memory EventArchive through the endpoint, so interleaving, type/text filtering, and
// keyset pagination are exercised over the same query contract the ClickHouse store implements, not a hand-rolled mock.

type timelineResponse struct {
	Events []struct {
		EventID   string `json:"event_id"`
		EventType string `json:"event_type"`
		HostID    string `json:"host_id"`
	} `json:"events"`
	NextCursor   string `json:"next_cursor"`
	TotalMatched int64  `json:"total_matched"`
}

func ev(id, host string, ts int64, eventType, payload string) visibilityapi.Event {
	return visibilityapi.Event{EventID: id, HostID: host, TimestampNs: ts, IngestedAtNs: ts, EventType: eventType, Payload: json.RawMessage(payload)}
}

// seededTimelineServer wires a handler over an archive pre-loaded with events. reader==false leaves the seam unset (503 path).
func newTimelineServer(t *testing.T, archive visibilityapi.EventArchive, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, slog.Default())
	if archive != nil {
		h.SetHostTimeline(archive)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func timelineArchive(t *testing.T, events ...visibilityapi.Event) *visibilitytestkit.MemArchive {
	t.Helper()
	a := visibilitytestkit.NewMemArchive()
	require.NoError(t, a.Insert(context.Background(), events))
	return a
}

func decodeTimeline(t *testing.T, resp *http.Response) timelineResponse {
	t.Helper()
	var out timelineResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// spec:server-rest-api/host-event-timeline-endpoint/timeline-interleaves-the-three-event-classes-in-time-order
func TestHostTimeline_InterleavesClassesNewestFirst(t *testing.T) {
	t.Parallel()
	a := timelineArchive(t,
		ev("x", "h1", 100, "exec", `{"pid":1,"path":"/bin/sh"}`),
		ev("n", "h1", 200, "network_connect", `{"pid":1,"remote_address":"1.2.3.4"}`),
		ev("d", "h1", 300, "dns_query", `{"pid":1,"query_name":"evil.example"}`),
		ev("other", "h2", 250, "exec", `{"pid":9,"path":"/bin/zsh"}`), // different host, excluded
	)
	srv := newTimelineServer(t, a, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/h1/timeline")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeTimeline(t, resp)
	require.Len(t, out.Events, 3)
	assert.EqualValues(t, 3, out.TotalMatched)
	// Newest-first, all three classes interleaved, host-scoped (h2's event absent).
	assert.Equal(t, []string{"dns_query", "network_connect", "exec"}, []string{out.Events[0].EventType, out.Events[1].EventType, out.Events[2].EventType})
	for _, e := range out.Events {
		assert.Equal(t, "h1", e.HostID)
	}
}

// spec:server-rest-api/host-event-timeline-endpoint/type-filter-restricts-the-classes-returned
func TestHostTimeline_TypeFilter(t *testing.T) {
	t.Parallel()
	a := timelineArchive(t,
		ev("x", "h1", 100, "exec", `{"pid":1,"path":"/bin/sh"}`),
		ev("d1", "h1", 300, "dns_query", `{"pid":1,"query_name":"a.example"}`),
		ev("d2", "h1", 400, "dns_query", `{"pid":1,"query_name":"b.example"}`),
	)
	srv := newTimelineServer(t, a, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/h1/timeline?type=dns_query")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeTimeline(t, resp)
	require.Len(t, out.Events, 2)
	assert.EqualValues(t, 2, out.TotalMatched) // total reflects the filtered class, not the whole host
	for _, e := range out.Events {
		assert.Equal(t, "dns_query", e.EventType)
	}
}

// spec:server-rest-api/host-event-timeline-endpoint/text-match-filters-by-payload-substring
func TestHostTimeline_TextMatch(t *testing.T) {
	t.Parallel()
	a := timelineArchive(t,
		ev("d1", "h1", 300, "dns_query", `{"pid":1,"query_name":"evil.example"}`),
		ev("d2", "h1", 400, "dns_query", `{"pid":1,"query_name":"benign.test"}`),
	)
	srv := newTimelineServer(t, a, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/h1/timeline?text=EVIL.example") // case-insensitive
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeTimeline(t, resp)
	require.Len(t, out.Events, 1)
	assert.Equal(t, "d1", out.Events[0].EventID)
}

// spec:server-rest-api/host-event-timeline-endpoint/keyset-pagination-is-stable-and-complete
func TestHostTimeline_KeysetPaginationStable(t *testing.T) {
	t.Parallel()
	a := timelineArchive(t,
		ev("e1", "h1", 100, "exec", `{"pid":1}`),
		ev("e2", "h1", 200, "network_connect", `{"pid":1,"remote_address":"1.1.1.1"}`),
		ev("e3", "h1", 300, "dns_query", `{"pid":1,"query_name":"a.example"}`),
		ev("e4", "h1", 400, "exec", `{"pid":2}`),
		ev("e5", "h1", 500, "network_connect", `{"pid":2,"remote_address":"2.2.2.2"}`),
	)
	srv := newTimelineServer(t, a, allowAllAuthZ{})

	seen := map[string]int{}
	cursor := ""
	pages := 0
	for {
		path := "/api/hosts/h1/timeline?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp := doGet(t, srv, path)
		out := decodeTimeline(t, resp)
		resp.Body.Close()
		for _, e := range out.Events {
			seen[e.EventID]++
		}
		pages++
		require.LessOrEqual(t, pages, 10, "pagination did not terminate")
		if out.NextCursor == "" {
			break
		}
		cursor = out.NextCursor
	}
	// Every event appeared exactly once across the pages.
	assert.Len(t, seen, 5)
	for id, n := range seen {
		assert.Equalf(t, 1, n, "event %s appeared %d times", id, n)
	}
}

// spec:server-rest-api/host-event-timeline-endpoint/an-unrecognized-event-type-is-rejected
func TestHostTimeline_UnknownTypeRejected(t *testing.T) {
	t.Parallel()
	srv := newTimelineServer(t, timelineArchive(t), allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/h1/timeline?type=exec,bogus_event")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHostTimeline_ErrorPaths(t *testing.T) {
	t.Parallel()
	t.Run("malformed cursor is 400", func(t *testing.T) {
		t.Parallel()
		srv := newTimelineServer(t, timelineArchive(t), allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/h1/timeline?cursor=@@not-base64@@")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("inverted window is 400", func(t *testing.T) {
		t.Parallel()
		srv := newTimelineServer(t, timelineArchive(t), allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/h1/timeline?from=500&to=100")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("non-numeric window is 400", func(t *testing.T) {
		t.Parallel()
		srv := newTimelineServer(t, timelineArchive(t), allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/h1/timeline?from=abc")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unset reader is 503", func(t *testing.T) {
		t.Parallel()
		srv := newTimelineServer(t, nil, allowAllAuthZ{}) // SetHostTimeline never called
		resp := doGet(t, srv, "/api/hosts/h1/timeline")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("denied authz is 403", func(t *testing.T) {
		t.Parallel()
		srv := newTimelineServer(t, timelineArchive(t), denyAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/h1/timeline")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// The timeline maps the from/to window and cursor to the filter it passes the archive: assert a bounded window round-trips by seeding
// events on both sides of it.
func TestHostTimeline_WindowBoundsEventTime(t *testing.T) {
	t.Parallel()
	a := timelineArchive(t,
		ev("old", "h1", 100, "exec", `{"pid":1}`),
		ev("mid", "h1", 250, "exec", `{"pid":2}`),
		ev("new", "h1", 900, "exec", `{"pid":3}`),
	)
	srv := newTimelineServer(t, a, allowAllAuthZ{})
	resp := doGet(t, srv, "/api/hosts/h1/timeline?from=200&to=300")
	defer resp.Body.Close()
	out := decodeTimeline(t, resp)
	require.Len(t, out.Events, 1)
	assert.Equal(t, "mid", out.Events[0].EventID)
}

func TestParseTimelineTypes(t *testing.T) {
	t.Parallel()
	t.Run("empty means all classes (nil, ok)", func(t *testing.T) {
		t.Parallel()
		types, ok := parseTimelineTypes("")
		assert.True(t, ok)
		assert.Nil(t, types)
	})
	t.Run("valid subset is parsed", func(t *testing.T) {
		t.Parallel()
		types, ok := parseTimelineTypes("exec,dns_query")
		assert.True(t, ok)
		assert.Equal(t, []string{"exec", "dns_query"}, types)
	})
	t.Run("duplicates are collapsed to a bounded set", func(t *testing.T) {
		t.Parallel()
		types, ok := parseTimelineTypes("exec,exec,exec,exec")
		assert.True(t, ok)
		assert.Equal(t, []string{"exec"}, types)
	})
	t.Run("an unrecognized class is rejected", func(t *testing.T) {
		t.Parallel()
		_, ok := parseTimelineTypes("exec,fork")
		assert.False(t, ok)
	})
}
