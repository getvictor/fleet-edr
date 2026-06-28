//go:build integration

// Concurrency coverage for issue #535 lever 2: a single replica now runs several processor workers that each claim disjoint event
// batches through the SKIP LOCKED claim (ADR-0011). This test drives the real Processor with concurrency > 1 against the real
// MySQL-backed EventLog and asserts the union of the workers' batches is a complete, duplicate-free forest: every seeded fork
// produced exactly one process row, the queue fully drained, and no event was claimed twice (which would surface as a duplicate row
// or a stuck queue).

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/concurrent-workers-within-one-replica-claim-disjoint-event-batches
func TestProcessor_IntraReplicaConcurrencyDrainsCompletely(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	db := full.Open(t)
	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	require.NoError(t, vis.ApplySchema(ctx))
	eventLog := vis.EventLog()

	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	builder := graph.NewBuilder(store, discardLogger())

	// Independent forks (distinct host/pid, no exec/exit) so the expected forest is exactly one row per fork regardless of how the
	// concurrent claims partition the queue: a duplicate would mean an event was processed twice, a shortfall means one was lost.
	const hosts = 40
	const forksPerHost = 25
	base := time.Now().UnixNano()
	var events []api.Event
	for h := range hosts {
		hostID := fmt.Sprintf("conc-host-%02d", h)
		for k := range forksPerHost {
			pid := 1000 + k
			ts := base + int64(h*forksPerHost+k)
			events = append(events, api.Event{
				EventID:      fmt.Sprintf("%s-fork-%d", hostID, pid),
				HostID:       hostID,
				TimestampNs:  ts,
				IngestedAtNs: ts,
				EventType:    "fork",
				Payload:      json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid)),
			})
		}
	}
	require.NoError(t, eventLog.Append(ctx, events))

	// Eight workers, batch 50: the 1000 events fan out across many disjoint SKIP LOCKED claims.
	proc := pipeline.NewProcessor(eventLog, builder, nil, discardLogger(), 5*time.Millisecond, 50, 8)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = proc.Run(runCtx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			// Fail rather than log: this is the only direct coverage of Run teardown, so a worker-loop deadlock that leaves the
			// goroutine alive must surface as a test failure, not a silent leak into the rest of the suite.
			t.Errorf("processor did not stop within 2s of cancel")
		}
	})

	require.Eventually(t, func() bool {
		pending, err := eventLog.CountPending(ctx)
		return err == nil && pending == 0
	}, 20*time.Second, 10*time.Millisecond, "the worker fleet must drain the whole queue")

	var rowCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id LIKE 'conc-host-%'`).Scan(&rowCount))
	assert.Equal(t, hosts*forksPerHost, rowCount, "every seeded fork must materialize exactly one row: no loss, no double-processing")

	var distinctKeys int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT host_id, pid FROM processes WHERE host_id LIKE 'conc-host-%' GROUP BY host_id, pid) k`).Scan(&distinctKeys))
	assert.Equal(t, hosts*forksPerHost, distinctKeys, "no (host,pid) was materialized more than once")
}
