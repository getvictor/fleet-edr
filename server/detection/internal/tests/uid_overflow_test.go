//go:build integration

// Integration coverage for issue #379: macOS uid_t/gid_t are unsigned 32-bit, so values like `nobody` (4294967294) and the unset
// sentinel KAUTH_UID_NONE (4294967295) overflowed the old signed-INT uid/gid columns and failed the insert with MySQL error 1264.
// Because the graph builder failed the whole batch on any per-event error and the processor re-fetched it forever, one such event
// wedged the detection pipeline fleet-wide. These tests pin both halves of the fix: the columns now hold the full range, and a
// permanently-failing event is dropped so the batch still advances.

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newBuilder(t *testing.T) (*graph.Builder, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	return graph.NewBuilder(store, discardLogger()), db
}

// spec:server-process-graph-builder/process-records-store-the-full-macos-uid-and-gid-range/a-process-owned-by-nobody-is-materialized
func TestProcessGraph_HighUIDProcessPersists(t *testing.T) {
	t.Parallel()
	b, db := newBuilder(t)
	ctx := t.Context()

	const nobodyUID int64 = 4294967294 // nobody, -2 as uint32
	const noneGID int64 = 4294967295   // the unset-id sentinel, -1 as uint32
	now := time.Now().UnixNano()
	events := []api.Event{
		{EventID: "fork-nobody", HostID: "h", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":4242,"parent_pid":1}`)},
		{EventID: "exec-nobody", HostID: "h", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":4242,"ppid":1,"path":"/usr/sbin/nobodyd","uid":%d,"gid":%d}`, nobodyUID, noneGID))},
	}

	require.NoError(t, b.ProcessBatch(ctx, events), "a uid/gid in the full uid_t range must not fail the batch")

	var uid, gid int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT uid, gid FROM processes WHERE host_id = 'h' AND pid = 4242`).Scan(&uid, &gid))
	assert.Equal(t, nobodyUID, uid)
	assert.Equal(t, noneGID, gid)
}

// spec:server-process-graph-builder/a-single-unpersistable-event-does-not-stall-batch-processing/a-poison-event-is-dropped-and-the-batch-advances
func TestProcessBatch_PermanentErrorDoesNotWedgeBatch(t *testing.T) {
	t.Parallel()
	b, db := newBuilder(t)
	ctx := t.Context()

	now := time.Now().UnixNano()
	// A host_id past the column's VARCHAR(255) is a permanent ER_DATA_TOO_LONG (1406): it fails identically on every retry, the
	// same poison-pill shape as the uid overflow. The valid event in the same batch must still be materialized.
	poisonHost := strings.Repeat("h", 300)
	events := []api.Event{
		{EventID: "good-fork", HostID: "good", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":10,"parent_pid":1}`)},
		{EventID: "poison-fork", HostID: poisonHost, TimestampNs: now + 1, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":11,"parent_pid":1}`)},
	}

	// The batch must report success despite the poison event so the processor marks it processed and advances, instead of
	// unclaiming and re-fetching it forever.
	require.NoError(t, b.ProcessBatch(ctx, events))

	var good int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = 'good' AND pid = 10`).Scan(&good))
	assert.Equal(t, 1, good, "the valid event in the batch is materialized")

	var poison int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE pid = 11`).Scan(&poison))
	assert.Equal(t, 0, poison, "the poison event is dropped, not stored")
}

// spec:server-process-graph-builder/a-single-unpersistable-event-does-not-stall-batch-processing/a-malformed-event-is-dropped-and-the-batch-advances
func TestProcessBatch_MalformedPayloadDoesNotWedgeBatch(t *testing.T) {
	t.Parallel()
	b, db := newBuilder(t)
	ctx := t.Context()

	now := time.Now().UnixNano()
	// A non-MySQL poison: the exec payload's pid is a string where an int is expected, so json.Unmarshal returns a deterministic
	// UnmarshalTypeError. Without classifying parse failures as permanent, this would fail the batch and wedge the pipeline the same
	// way the uid overflow did (issue #379 review follow-up).
	events := []api.Event{
		{EventID: "good-fork-2", HostID: "good2", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":20,"parent_pid":1}`)},
		{EventID: "malformed-exec", HostID: "good2", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":"not-a-number"}`)},
	}

	require.NoError(t, b.ProcessBatch(ctx, events))

	var good int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = 'good2' AND pid = 20`).Scan(&good))
	assert.Equal(t, 1, good, "the valid event is materialized despite the malformed sibling")
}
