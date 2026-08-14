//go:build integration

package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
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

// maxClickHouseDBNameLen is the longest database name this ClickHouse accepts. The server stores database metadata at
// /var/lib/clickhouse/metadata/<name>.sql and writes it through a <name>.sql.tmp intermediate, so the name plus that 8-byte
// suffix has to fit the filesystem's 255-byte NAME_MAX. Measured against the pinned 24.8 image: 247 succeeds, 248 fails with
// "Cannot open file ... errno 36". The MySQL side caps at 64 for the same reason (a hard identifier ceiling), see sanitizeDBName.
const maxClickHouseDBNameLen = 247

// safeDBName builds a per-test ClickHouse database name from the test name, keeping only [a-z0-9_] so it is always a valid unquoted
// identifier (subtest names carry '/', spaces, etc.). Two extra components make the name collision-free, mirroring the MySQL side
// in server/testdb:
//
//   - testdb.ProcessSalt() scopes the name to this `go test` process. The DDL below is DROP-then-CREATE, so without the salt two
//     concurrent runs of the same test against one shared dev ClickHouse (two worktrees on one machine, or a sharded CI run) each
//     drop the other's live database mid-test.
//   - A hash of the ORIGINAL name disambiguates subtests that the character loop collapses onto each other ("T/A" and "T.A" both
//     reduce to "t_a"), which the salt alone does not fix because both collide within the same process.
func safeDBName(name string) string {
	sum := sha256.Sum256([]byte(name))
	suffixHex := hex.EncodeToString(sum[:4])

	var b strings.Builder
	b.WriteString("edr_test_")
	b.WriteString(testdb.ProcessSalt())
	b.WriteString("_")
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}

	// Truncate the readable segment only, never the salt or the hash: those two carry the entire uniqueness guarantee, while the
	// readable part exists so a human can tell which test owns a leftover database. Byte-slicing is safe here because the loop
	// above emits exactly one ASCII byte per input rune, so there is no multi-byte sequence to cut in half.
	readable := b.String()
	if maxReadable := maxClickHouseDBNameLen - 1 - len(suffixHex); len(readable) > maxReadable {
		readable = readable[:maxReadable]
	}
	return readable + "_" + suffixHex
}

// openTestArchive provisions a per-test ClickHouse database on the instance named by EDR_CLICKHOUSE_TEST_DSN (so parallel tests do
// not collide), wires the visibility context over a MySQL test DB plus that ClickHouse DB via bootstrap, applies both schemas, and
// returns the EventArchive.
func openTestArchive(t *testing.T) visibilityapi.EventArchive {
	t.Helper()
	arch, _ := openTestArchiveWithHandle(t)
	return arch
}

// openTestArchiveWithHandle is openTestArchive plus the raw ClickHouse handle, for the few tests that must run a maintenance statement
// the EventArchive API does not expose (e.g. OPTIMIZE ... FINAL to force TTL application deterministically). The handle stays open
// until test cleanup, so a test may use it for the whole test body.
func openTestArchiveWithHandle(t *testing.T) (visibilityapi.EventArchive, *sqlx.DB) {
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
	return vis.EventArchive(), chDB
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

// spec:server-event-ingestion/durable-event-archive-with-bounded-retention/an-accepted-event-is-queryable-from-the-archive
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

// spec:server-event-ingestion/durable-event-archive-with-bounded-retention/a-re-delivered-event-is-not-duplicated-in-the-archive
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

// spec:server-event-ingestion/durable-event-archive-with-bounded-retention/an-event-older-than-the-retention-window-ages-out
func TestEventArchive_RetentionTTLExpiresOldEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch, chDB := openTestArchiveWithHandle(t)

	// Two events on the same (host, pid), differing only in ingest age. ingested_date is materialized from ingested_at_ns, so the recent
	// event lands inside the 30-day TTL window and the old event, stamped ~40 days back, lands outside it. dayNs is a fixed span; nowNs
	// only anchors "recent" to today so the recent event never itself ages out mid-test.
	const dayNs = int64(24 * time.Hour)
	nowNs := time.Now().UnixNano()
	recentIngestedNs := nowNs
	oldIngestedNs := nowNs - 40*dayNs

	const (
		host      = "hretention"
		pid       = 55
		recentID  = "retention-recent"
		expiredID = "retention-expired"
	)
	recent := archiveEvent(recentID, host, "network_connect", nowNs+100, pid)
	recent.IngestedAtNs = recentIngestedNs
	expired := archiveEvent(expiredID, host, "network_connect", oldIngestedNs+200, pid)
	expired.IngestedAtNs = oldIngestedNs
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{recent, expired}))

	// The read window bounds ingested_at_ns and spans both ingest times, so absent TTL both events would be returned; the surviving
	// event below is therefore filtered by retention, not by the window. (A "both present before expiry" pre-read would race the
	// background merge scheduler, which can apply TTL on its own before the read settles, so it is left out deliberately.)
	window := httpserver.TimeRange{FromNs: 0, ToNs: nowNs + 1_000_000}

	// ClickHouse applies native TTL during merges; OPTIMIZE ... FINAL forces one synchronously so the expiry is deterministic in-test
	// rather than waiting on the background merge scheduler. This is the maintenance path openTestArchiveWithHandle exposes chDB for.
	_, err := chDB.ExecContext(ctx, "OPTIMIZE TABLE events FINAL")
	require.NoError(t, err)

	// After expiry the old event is absent from query results and the recent one still present, over the same window. Eventually absorbs
	// any brief read-after-merge lag.
	var after []visibilityapi.Event
	require.Eventually(t, func() bool {
		after, err = arch.NetworkEventsForProcess(ctx, host, pid, window)
		return err == nil && len(after) == 1
	}, 5*time.Second, 100*time.Millisecond, "TTL leaves exactly the in-window event")
	assert.Equal(t, []string{recentID}, eventIDs(after), "the event older than the 30-day window ages out; the recent event survives")

	// EventsByIDs has no time window at all, so it too must not resurface the expired row: TTL removed it from the archive, not merely
	// from the windowed correlation read.
	byID, err := arch.EventsByIDs(ctx, []string{recentID, expiredID})
	require.NoError(t, err)
	assert.Equal(t, []string{recentID}, eventIDs(byID), "the expired event is gone from the archive entirely, not just the windowed read")
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
// spec:server-rest-api/fleet-wide-connection-and-dns-search-endpoints/absent-artifact-value-lists-recent-events
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

	// An empty artifact value lists every event of the type (the recent-events mode), across hosts, still scoped to the type. The
	// browse deliberately skips the fleet-wide COUNT (the more expensive half on a large archive), so TotalMatched is not computed.
	res, err = arch.SearchEvents(ctx, visibilityapi.EventSearchFilter{
		EventType: "network_connect", FromNs: window.FromNs, ToNs: window.ToNs,
	}, "", 50)
	require.NoError(t, err)
	assert.EqualValues(t, visibilityapi.TotalNotCounted, res.TotalMatched, "the recent-events browse skips the count")
	require.Len(t, res.Events, 3, "no artifact filter lists all connection events")
	ids = eventIDSet(res.Events)
	assert.True(t, ids["c-a"] && ids["c-b"] && ids["c-other"], "includes every connection regardless of remote address")
	assert.False(t, ids["d-a"], "still scoped to the connection event type")
}

// TestEventArchive_EventsByTypeForHost exercises the correlation read the sensor-tamper rule asks the archive for: what
// did THIS host's own event stream do in the seconds after a capture provider stopped. The three exclusions are the ones
// that would each break the rule in a different direction: another host's recovery would suppress a real tamper, another
// event type would be parsed as a transition, and an event outside the window would answer a question about the wrong
// moment.
//
// spec:server-detection-rules-engine/edr-sensor-tamper-detection/an-upgrade-cutover-does-not-fire
func TestEventArchive_EventsByTypeForHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)
	base := time.Now().UnixNano()
	const transition = "sensor_provider_transition"
	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveEvent("stop", "hostA", transition, base, 1),
		archiveEvent("resume", "hostA", transition, base+int64(time.Second), 1),
		archiveEvent("other-host", "hostB", transition, base+int64(time.Second), 1),
		archiveEvent("other-type", "hostA", "exec", base+int64(time.Second), 1),
		archiveEvent("too-late", "hostA", transition, base+int64(time.Minute), 1),
	}))

	got, err := arch.EventsByTypeForHost(ctx, "hostA", transition, httpserver.TimeRange{
		FromNs: base, ToNs: base + int64(5*time.Second),
	})
	require.NoError(t, err)
	ids := make([]string, len(got))
	for i, e := range got {
		ids[i] = e.EventID
	}
	assert.Equal(t, []string{"stop", "resume"}, ids,
		"this host, this type, inside the window, oldest first")
}

// TestEventArchive_EventsByTypeForHostOverflow pins the same overflow contract the in-memory archive has, against real ClickHouse.
// The two implementations have to agree here specifically: rule tests run against the fake, so a fake that returns everything while
// production silently truncates would hide the one failure the cap introduces.
func TestEventArchive_EventsByTypeForHostOverflow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch := openTestArchive(t)
	base := time.Now().UnixNano()
	const transition = "sensor_provider_transition"
	const cap = 1000

	events := make([]visibilityapi.Event, 0, cap+1)
	for i := range cap + 1 {
		events = append(events, archiveEvent(fmt.Sprintf("ovf%05d", i), "hostOvf", transition, base+int64(i), 1))
	}
	require.NoError(t, arch.Insert(ctx, events))

	_, err := arch.EventsByTypeForHost(ctx, "hostOvf", transition, httpserver.TimeRange{
		FromNs: base, ToNs: base + int64(cap+1),
	})
	require.ErrorIs(t, err, visibilityapi.ErrEventsTruncated)

	// Exactly at the cap is a complete answer.
	got, err := arch.EventsByTypeForHost(ctx, "hostOvf", transition, httpserver.TimeRange{
		FromNs: base, ToNs: base + int64(cap-1),
	})
	require.NoError(t, err)
	assert.Len(t, got, cap)
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

	// The store enforces the timeline allowlist itself: a caller explicitly requesting a non-timeline class (fork) gets no rows,
	// and a mixed request keeps only the timeline classes. This holds even though the handler already rejects unknown ?type= values,
	// so the archive contract cannot be violated by a caller that bypasses the handler.
	forkOnly := window
	forkOnly.EventTypes = []string{"fork"}
	res, err = arch.HostTimeline(ctx, forkOnly, "", 50)
	require.NoError(t, err)
	assert.Empty(t, res.Events)
	assert.EqualValues(t, 0, res.TotalMatched)

	mixed := window
	mixed.EventTypes = []string{"exec", "fork"}
	res, err = arch.HostTimeline(ctx, mixed, "", 50)
	require.NoError(t, err)
	require.Len(t, res.Events, 1)
	assert.Equal(t, "t-exec", res.Events[0].EventID) // exec kept, fork dropped
}

func eventIDSet(events []visibilityapi.Event) map[string]bool {
	m := make(map[string]bool, len(events))
	for _, e := range events {
		m[e.EventID] = true
	}
	return m
}

func eventIDs(events []visibilityapi.Event) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	return ids
}
