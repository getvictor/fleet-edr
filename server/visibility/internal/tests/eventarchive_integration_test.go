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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/testdb"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
	chstore "github.com/fleetdm/edr/server/visibility/internal/clickhouse"
)

// openTestArchive provisions a per-test ClickHouse database on the instance named by EDR_CLICKHOUSE_TEST_DSN (so parallel tests do
// not collide), wires the visibility context over a MySQL test DB plus that ClickHouse DB via bootstrap, applies both schemas, and
// returns the EventArchive. It skips when either DSN is unset, matching the project's other DB-backed tests.
func clickhouseTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EDR_CLICKHOUSE_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_CLICKHOUSE_TEST_DSN not set")
	}
	return dsn
}

func openTestArchive(t *testing.T) visibilityapi.EventArchive {
	t.Helper()
	dsn := clickhouseTestDSN(t)
	ctx := context.Background()

	admin, err := chstore.Open(ctx, dsn)
	require.NoError(t, err)
	defer admin.Close() //nolint:errcheck

	dbName := "edr_test_" + strings.ToLower(strings.NewReplacer("/", "_", "#", "_").Replace(t.Name()))
	_, err = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+dbName)
	require.NoError(t, err)
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + dbName
	chDB, err := chstore.Open(ctx, u.String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
		_ = chDB.Close()
	})

	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: testdb.Open(t), ClickHouseDB: chDB})
	require.NoError(t, err)
	require.NoError(t, vis.ApplySchema(ctx))
	return vis.EventArchive()
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

	require.NoError(t, arch.Insert(ctx, []visibilityapi.Event{
		archiveEvent("nc1", "h1", "network_connect", 100, 42),
		archiveEvent("dns1", "h1", "dns_query", 200, 42),
		archiveEvent("exec1", "h1", "exec", 150, 42),               // not a network/dns event: excluded
		archiveEvent("nc-other", "h1", "network_connect", 120, 99), // different pid: excluded
	}))

	got, err := arch.NetworkEventsForProcess(ctx, "h1", 42, httpserver.TimeRange{FromNs: 0, ToNs: 1_000_000})
	require.NoError(t, err)

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

	batch := []visibilityapi.Event{archiveEvent("dup", "h1", "network_connect", 100, 7)}
	require.NoError(t, arch.Insert(ctx, batch))
	require.NoError(t, arch.Insert(ctx, batch), "re-inserting the same event_id is not an error")

	got, err := arch.NetworkEventsForProcess(ctx, "h1", 7, httpserver.TimeRange{FromNs: 0, ToNs: 1_000_000})
	require.NoError(t, err)
	assert.Len(t, got, 1, "FINAL collapses the at-least-once duplicate to a single row")
}
