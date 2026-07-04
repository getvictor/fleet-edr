//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/testdb"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
	chstore "github.com/fleetdm/edr/server/visibility/internal/clickhouse"
)

// clickhouseTestDSN returns the ClickHouse test DSN, skipping when EDR_CLICKHOUSE_TEST_DSN is unset (matching the project's other
// DB-backed tests' EDR_TEST_DSN behavior).
func clickhouseTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EDR_CLICKHOUSE_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_CLICKHOUSE_TEST_DSN not set")
	}
	return dsn
}

// safeDBName builds a per-test ClickHouse database name from the test name, keeping only [a-z0-9_] so it is always a valid unquoted
// identifier (subtest names carry '/', spaces, etc.).
func safeDBName(name string) string {
	var b strings.Builder
	b.WriteString("edr_test_")
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// openTestArchive provisions a per-test ClickHouse database on the instance named by EDR_CLICKHOUSE_TEST_DSN (so parallel tests do
// not collide), wires the visibility context over a MySQL test DB plus that ClickHouse DB via bootstrap, applies both schemas, and
// returns the EventArchive.
func openTestArchive(t *testing.T) visibilityapi.EventArchive {
	t.Helper()
	dsn := clickhouseTestDSN(t)
	ctx := context.Background()

	admin, err := chstore.Open(ctx, dsn)
	require.NoError(t, err)

	dbName := safeDBName(t.Name())
	_, err = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+dbName)
	require.NoError(t, err)
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + dbName
	chDB, err := chstore.Open(ctx, u.String())
	require.NoError(t, err)
	// admin stays open until cleanup so the DROP DATABASE below runs on a live connection (closing it here would leak the test DB).
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
		_ = chDB.Close()
		_ = admin.Close()
	})

	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: testdb.Open(t), ClickHouseDB: chDB})
	require.NoError(t, err)
	require.NoError(t, vis.ApplySchema(ctx))
	return vis.EventArchive()
}

// readNetworkEvents polls NetworkEventsForProcess until it returns wantN rows or the deadline elapses, absorbing any brief
// read-after-insert lag on a busy ClickHouse without flaking. Note: events MUST carry recent nanosecond timestamps; the table's TTL
// (ingested_date + 30 days) would otherwise expire rows whose ingested_at_ns maps to an old date (e.g. 1970 for tiny test values).
func readNetworkEvents(t *testing.T, arch visibilityapi.EventArchive, host string, pid, wantN int, tr httpserver.TimeRange) []visibilityapi.Event {
	t.Helper()
	var got []visibilityapi.Event
	require.Eventually(t, func() bool {
		var err error
		got, err = arch.NetworkEventsForProcess(context.Background(), host, pid, tr)
		return err == nil && len(got) == wantN
	}, 5*time.Second, 100*time.Millisecond, "expected %d network/dns events for pid %d", wantN, pid)
	return got
}

func archiveEvent(id, host, etype string, ts int64, pid int) visibilityapi.Event {
	return visibilityapi.Event{
		EventID:      id,
		HostID:       host,
		TimestampNs:  ts,
		IngestedAtNs: ts + 1,
		EventType:    etype,
		Platform:     "darwin",
		Payload:      json.RawMessage(`{"pid":` + strconv.Itoa(pid) + `}`),
	}
}

func TestEventArchive_InsertAndCorrelationRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)

	// Recent base so ingested_date lands inside the 30-day TTL window (see readNetworkEvents).
	base := time.Now().UnixNano()
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveEvent("nc1", "h1", "network_connect", base+100, 42),
		archiveEvent("dns1", "h1", "dns_query", base+200, 42),
		archiveEvent("exec1", "h1", "exec", base+150, 42),               // not a network/dns event: excluded
		archiveEvent("nc-other", "h1", "network_connect", base+120, 99), // different pid: excluded
	}))

	got := readNetworkEvents(t, arch, "h1", 42, 2, httpserver.TimeRange{FromNs: 0, ToNs: base + 1_000_000})

	ids := make([]string, len(got))
	for i, e := range got {
		ids[i] = e.EventID
	}
	assert.Equal(t, []string{"nc1", "dns1"}, ids, "only this pid's network_connect + dns_query, ordered by timestamp")
	assert.JSONEq(t, `{"pid":42}`, string(got[0].Payload), "payload round-trips from the archive")
	assert.Equal(t, "darwin", got[0].Platform, "platform round-trips from the archive")
}

func TestEventArchive_ErrorsOnClosedConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := chstore.Open(ctx, clickhouseTestDSN(t))
	require.NoError(t, err)
	store, err := chstore.New(db)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	require.Error(t, store.Insert(ctx, []visibilityapi.Event{archiveEvent("x", "h1", "network_connect", 1, 1)}),
		"insert on a closed connection surfaces the error")
	_, err = store.NetworkEventsForProcess(ctx, "h1", 1, httpserver.TimeRange{FromNs: 0, ToNs: 1})
	require.Error(t, err, "read on a closed connection surfaces the error")
	_, err = store.EventsByIDs(ctx, []string{"x"})
	require.Error(t, err, "events-by-ids on a closed connection surfaces the error")
}

func TestEventArchive_EventsByIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)

	// Recent base so ingested_date lands inside the 30-day TTL window (see readNetworkEvents).
	base := time.Now().UnixNano()
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveEvent("ev-b", "h1", "exec", base+200, 1),
		archiveEvent("ev-a", "h1", "network_connect", base+100, 1),
		archiveEvent("ev-c", "h1", "dns_query", base+300, 1),
	}))

	// EventsByIDs backs self-contained alert evidence: it returns the requested envelopes ordered by (timestamp_ns, event_id), across
	// any event_type, and silently omits an id with no surviving row (best-effort, so an aged-out event never fails alert creation).
	var got []visibilityapi.Event
	require.Eventually(t, func() bool {
		var err error
		got, err = arch.EventsByIDs(ctx, []string{"ev-b", "ev-a", "missing"})
		return err == nil && len(got) == 2
	}, 5*time.Second, 100*time.Millisecond, "EventsByIDs returns the two known events, omitting the unknown id")

	ids := []string{got[0].EventID, got[1].EventID}
	assert.Equal(t, []string{"ev-a", "ev-b"}, ids, "ordered by (timestamp_ns, event_id) regardless of request order")
	assert.Equal(t, "network_connect", got[0].EventType)
	assert.Equal(t, "darwin", got[0].Platform, "platform round-trips from the archive via EventsByIDs")
	assert.JSONEq(t, `{"pid":1}`, string(got[0].Payload), "payload round-trips from the archive")

	empty, err := arch.EventsByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty, "no ids requested returns no rows without a query")
}

func TestEventArchive_IdempotentInsert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)

	base := time.Now().UnixNano()
	batch := []visibilityapi.Event{archiveEvent("dup", "h1", "network_connect", base+100, 7)}
	require.NoError(t, arch.Insert(ctx, batch))
	require.NoError(t, arch.Insert(ctx, batch), "re-inserting the same event_id is not an error")

	got := readNetworkEvents(t, arch, "h1", 7, 1, httpserver.TimeRange{FromNs: 0, ToNs: base + 1_000_000})
	assert.Len(t, got, 1, "FINAL collapses the at-least-once duplicate to a single row")
}

// archiveArtifactEvent builds a network_connect or dns_query event carrying the artifact field the fleet-wide search matches on
// (remote_address for connections, query_name for DNS). base + offset keeps ingested_date inside the 30-day TTL window.
func archiveArtifactEvent(id, host, etype string, ts int64, artifact string) visibilityapi.Event {
	field := "remote_address"
	if etype == "dns_query" {
		field = "query_name"
	}
	payload, _ := json.Marshal(map[string]any{"pid": 1, field: artifact})
	return visibilityapi.Event{
		EventID:      id,
		HostID:       host,
		TimestampNs:  ts,
		IngestedAtNs: ts + 1,
		EventType:    etype,
		Platform:     "darwin",
		Payload:      payload,
	}
}

// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/connection-search-finds-a-remote-address-across-hosts
// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/dns-search-finds-a-query-name-across-hosts
// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/host-filter-scopes-the-search
func TestEventArchive_SearchEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)
	base := time.Now().UnixNano()
	const badIP = "203.0.113.7"
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveArtifactEvent("c-a", "hostA", "network_connect", base+10, badIP),
		archiveArtifactEvent("c-b", "hostB", "network_connect", base+20, badIP),
		archiveArtifactEvent("c-other", "hostA", "network_connect", base+30, "10.0.0.1"), // different IP
		archiveArtifactEvent("d-a", "hostA", "dns_query", base+40, "evil.example"),
		archiveArtifactEvent("d-b", "hostB", "dns_query", base+50, "evil.example"),
		archiveArtifactEvent("d-other", "hostA", "dns_query", base+60, "good.example"), // different domain
	}))
	window := httpserver.TimeRange{FromNs: 0, ToNs: base + 1_000_000}

	// Connection search: the bad IP on both hosts, not the other IP.
	res, err := arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{
		EventType: "network_connect", Value: badIP, FromNs: window.FromNs, ToNs: window.ToNs,
	}, "", 50)
	require.NoError(t, err)
	assert.EqualValues(t, 2, res.TotalMatched)
	ids := eventIDSet(res.Events)
	assert.True(t, ids["c-a"] && ids["c-b"] && !ids["c-other"], "matches the bad IP on both hosts, excludes the other IP")

	// DNS search: the domain on both hosts, not the other domain.
	res, err = arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{
		EventType: "dns_query", Value: "evil.example", FromNs: window.FromNs, ToNs: window.ToNs,
	}, "", 50)
	require.NoError(t, err)
	assert.EqualValues(t, 2, res.TotalMatched)
	ids = eventIDSet(res.Events)
	assert.True(t, ids["d-a"] && ids["d-b"] && !ids["d-other"], "matches the domain on both hosts, excludes the other domain")

	// Host filter scopes the connection search to one host.
	res, err = arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{
		EventType: "network_connect", Value: badIP, HostID: "hostB", FromNs: window.FromNs, ToNs: window.ToNs,
	}, "", 50)
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.Equal(t, "hostB", res.Events[0].HostID)
}

// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/keyset-pagination-is-stable-and-complete
func TestEventArchive_SearchEventsPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)
	base := time.Now().UnixNano()
	const ip = "198.51.100.4"
	const total = 12
	batch := make([]visibilityapi.Event, total)
	for i := range total {
		// Some share a timestamp so the (timestamp_ns, event_id) compound keyset is exercised, not timestamp alone.
		batch[i] = archiveArtifactEvent("p-"+strconv.Itoa(i), "hostA", "network_connect", base+int64(i/3), ip)
	}
	require.NoError(t, arch.Insert(ctx, batch))
	window := httpserver.TimeRange{FromNs: 0, ToNs: base + 1_000_000}

	full, err := arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{EventType: "network_connect", Value: ip, FromNs: window.FromNs, ToNs: window.ToNs}, "", total+5)
	require.NoError(t, err)
	require.Len(t, full.Events, total)
	want := make([]string, len(full.Events))
	for i, e := range full.Events {
		want[i] = e.EventID
	}

	// Page size 5: concatenation of pages reproduces the unpaginated order exactly, no dupes, no skips.
	var got []string
	cursor := ""
	for {
		page, err := arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{EventType: "network_connect", Value: ip, FromNs: window.FromNs, ToNs: window.ToNs}, cursor, 5)
		require.NoError(t, err)
		for _, e := range page.Events {
			got = append(got, e.EventID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	assert.Equal(t, want, got, "paging reproduces the full newest-first order exactly")
}

// TestEventArchive_HostTimeline exercises the merged host timeline over real ClickHouse: exec/network/DNS interleaved newest-first,
// host scoping, the type filter, the payload text match, and the event-time window bound (issue #583).
func TestEventArchive_HostTimeline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)
	base := time.Now().UnixNano()
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveEvent("t-exec", "hostA", "exec", base+10, 1),
		archiveArtifactEvent("t-net", "hostA", "network_connect", base+20, "203.0.113.7"),
		archiveArtifactEvent("t-dns", "hostA", "dns_query", base+30, "evil.example"),
		archiveEvent("t-fork", "hostA", "fork", base+25, 2),      // not a timeline class: excluded even with no type filter
		archiveEvent("t-otherhost", "hostB", "exec", base+40, 3), // different host: excluded
	}))
	window := visibilityapi.HostTimelineFilter{HostID: "hostA", FromNs: 0, ToNs: base + 1_000_000}

	// No type filter: the three timeline classes for hostA, newest-first, fork and the other host excluded.
	res, err := arch.HostTimeline(ctx, window, "", 50)
	require.NoError(t, err)
	assert.EqualValues(t, 3, res.TotalMatched)
	var order []string
	for _, e := range res.Events {
		order = append(order, e.EventType)
	}
	assert.Equal(t, []string{"dns_query", "network_connect", "exec"}, order)

	// Type filter narrows to DNS.
	dnsOnly := window
	dnsOnly.EventTypes = []string{"dns_query"}
	res, err = arch.HostTimeline(ctx, dnsOnly, "", 50)
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.Equal(t, "t-dns", res.Events[0].EventID)

	// Text match against the payload (case-insensitive) keeps only the DNS event.
	textFilter := window
	textFilter.Text = "EVIL.example"
	res, err = arch.HostTimeline(ctx, textFilter, "", 50)
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.Equal(t, "t-dns", res.Events[0].EventID)

	// Window bounds event time: a narrow window around the network event keeps only it.
	narrow := visibilityapi.HostTimelineFilter{HostID: "hostA", FromNs: base + 15, ToNs: base + 25}
	res, err = arch.HostTimeline(ctx, narrow, "", 50)
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.Equal(t, "t-net", res.Events[0].EventID)
}

func eventIDSet(events []visibilityapi.Event) map[string]bool {
	m := make(map[string]bool, len(events))
	for _, e := range events {
		m[e.EventID] = true
	}
	return m
}
