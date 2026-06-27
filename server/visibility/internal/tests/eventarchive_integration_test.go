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
