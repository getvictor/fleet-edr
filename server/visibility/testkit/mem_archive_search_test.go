package testkit

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/visibility/api"
)

func artifactEvent(id, host, etype string, ts int64, field, value string) api.Event {
	payload, _ := json.Marshal(map[string]any{"pid": 1, field: value})
	return api.Event{EventID: id, HostID: host, TimestampNs: ts, IngestedAtNs: ts, EventType: etype, Payload: payload}
}

// TestMemArchive_SearchEvents exercises the in-memory search the operator handler tests rely on: it must match the ClickHouse read
// semantics (event type + artifact value + optional host + ingest window, newest-first) so a handler test passing against the fake
// reflects real behaviour.
func TestMemArchive_SearchEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemArchive()
	require.NoError(t, m.Insert(ctx, []api.Event{
		artifactEvent("c-a", "hostA", "network_connect", 100, "remote_address", "1.1.1.1"),
		artifactEvent("c-b", "hostB", "network_connect", 200, "remote_address", "1.1.1.1"),
		artifactEvent("c-x", "hostA", "network_connect", 300, "remote_address", "2.2.2.2"),
		artifactEvent("d-a", "hostA", "dns_query", 400, "query_name", "evil.example"),
	}))

	t.Run("connection search matches the IP across hosts, newest-first", func(t *testing.T) {
		t.Parallel()
		res, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "network_connect", Value: "1.1.1.1"}, "", 50)
		require.NoError(t, err)
		assert.EqualValues(t, 2, res.TotalMatched)
		require.Len(t, res.Events, 2)
		assert.Equal(t, "c-b", res.Events[0].EventID, "newest first")
		assert.Equal(t, "c-a", res.Events[1].EventID)
	})

	t.Run("dns search matches the query name", func(t *testing.T) {
		t.Parallel()
		res, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "dns_query", Value: "evil.example"}, "", 50)
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
		assert.Equal(t, "d-a", res.Events[0].EventID)
	})

	t.Run("host filter scopes the search", func(t *testing.T) {
		t.Parallel()
		res, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "network_connect", Value: "1.1.1.1", HostID: "hostB"}, "", 50)
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
		assert.Equal(t, "hostB", res.Events[0].HostID)
	})

	t.Run("ingest window bounds the search", func(t *testing.T) {
		t.Parallel()
		res, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "network_connect", Value: "1.1.1.1", FromNs: 150, ToNs: 250}, "", 50)
		require.NoError(t, err)
		require.Len(t, res.Events, 1)
		assert.Equal(t, "c-b", res.Events[0].EventID)
	})

	t.Run("unsupported event type errors", func(t *testing.T) {
		t.Parallel()
		_, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "exec", Value: "x"}, "", 50)
		require.Error(t, err)
	})

	t.Run("malformed cursor errors", func(t *testing.T) {
		t.Parallel()
		_, err := m.SearchEvents(ctx, api.EventSearchFilter{EventType: "network_connect", Value: "1.1.1.1"}, "not!valid", 50)
		assert.ErrorIs(t, err, api.ErrInvalidEventCursor)
	})
}

// TestMemArchive_SearchEventsPagination pins the keyset completeness the handler pagination relies on: paging at any size reproduces
// the full newest-first order exactly, including events sharing a timestamp.
func TestMemArchive_SearchEventsPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemArchive()
	const total = 10
	batch := make([]api.Event, total)
	for i := range total {
		batch[i] = artifactEvent("p-"+strconv.Itoa(i), "h", "network_connect", int64(i/3), "remote_address", "9.9.9.9")
	}
	require.NoError(t, m.Insert(ctx, batch))
	filter := api.EventSearchFilter{EventType: "network_connect", Value: "9.9.9.9"}

	full, err := m.SearchEvents(ctx, filter, "", total+5)
	require.NoError(t, err)
	require.Len(t, full.Events, total)
	want := make([]string, total)
	for i, e := range full.Events {
		want[i] = e.EventID
	}

	// Small, exact-divisor, and non-divisor page sizes: each must reproduce the full order.
	for _, size := range []int{1, 2, 3, 4, 7} {
		var got []string
		cursor := ""
		for {
			page, err := m.SearchEvents(ctx, filter, cursor, size)
			require.NoError(t, err)
			for _, e := range page.Events {
				got = append(got, e.EventID)
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
		assert.Equal(t, want, got, "page size %d reproduces the full order", size)
	}
}
