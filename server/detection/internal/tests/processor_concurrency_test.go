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

	"github.com/fleetdm/edr/server/coordination/leader"
	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
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

	// Eight workers, batch 50: the 1000 events fan out across many disjoint per-host claims. Forty hosts against eight workers is
	// also the throughput half of issue #717: serializing each host must not serialize the fleet, so the drain below still has to
	// complete well inside its deadline with every worker busy on a different host.
	proc, err := pipeline.NewProcessor(eventLog, builder, nil, pipeline.ProcessorOptions{
		Logger:      discardLogger(),
		Interval:    5 * time.Millisecond,
		Batch:       50,
		Concurrency: 8,
		Coordinator: leader.NewMySQL(db, discardLogger()),
		// The per-test pool is capped at 4 connections and a locked worker holds two, so the processor sizes 8 workers down to the
		// share the pool can serve. Passing the real budget is what turns that from a silent stall into a logged reduction, and the
		// drain below then proves the reduced fleet still finishes: a fleet sized to the pool is the point, not a fleet of eight.
		ConnBudget: db.Stats().MaxOpenConnections,
	})
	require.NoError(t, err)
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

// TestDetection_ProcessorConcurrencyReportsTheEffectiveFanOut pins what ProcessorConcurrency answers, which is the question issue
// #962 was decided on: not "how many workers were configured" but "how many will actually run".
//
// The three cases are the three answers a caller can get, and the middle one is the regression itself. A harness that wires no
// coordinator gets a single worker however many it asked for, silently and with only a WARN, so the scale gate spent three weeks
// measuring one worker while believing it measured four and read the shortfall as a throughput regression in the product. An
// accessor that reported the REQUESTED count would have kept that hidden, so the assertion here is specifically that the clamped
// case reports 1.
func TestDetection_ProcessorConcurrencyReportsTheEffectiveFanOut(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mode bootstrap.Mode
		// withCoordinator decides the clamp: without one the processor refuses to run more than a single worker, because nothing
		// would keep two of them off the same host's stream (issue #717).
		withCoordinator bool
		// maxOpenConns sizes the pool BEFORE bootstrap, since the processor reads the cap at construction to decide what it can
		// afford. A locked worker holds two connections and workers take at most half the pool, so four workers need sixteen
		// obtainable connections on top of the three the leader-gated sweeps pin for the life of the process.
		maxOpenConns int
		requested    int
		want         int
	}{
		{
			name:            "the production shape reports the fan-out it was given",
			mode:            bootstrap.ModeFull,
			withCoordinator: true,
			maxOpenConns:    24,
			requested:       4,
			want:            4,
		},
		{
			name:            "no coordinator reports the single worker it will really run, not the four requested",
			mode:            bootstrap.ModeFull,
			withCoordinator: false,
			maxOpenConns:    24,
			requested:       4,
			want:            1,
		},
		{
			name:            "a mode that wires no processor reports zero rather than a fan-out it does not have",
			mode:            bootstrap.ModeIntake,
			withCoordinator: true,
			maxOpenConns:    24,
			requested:       4,
			want:            0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			db := full.Open(t)
			db.SetMaxOpenConns(tc.maxOpenConns)
			db.SetMaxIdleConns(tc.maxOpenConns)
			vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
			require.NoError(t, err)
			require.NoError(t, vis.ApplySchema(ctx))

			deps := bootstrap.Deps{
				DB:                   db,
				Mode:                 tc.mode,
				ProcessInterval:      20 * time.Millisecond,
				ProcessBatch:         100,
				ProcessConcurrency:   tc.requested,
				StaleProcessTTL:      time.Hour,
				StaleProcessInterval: 20 * time.Millisecond,
				RetentionDays:        30,
				RetentionInterval:    20 * time.Millisecond,
				AuthZ:                allowAllAuthZ{},
				EventLog:             vis.EventLog(),
				EventArchive:         detectiontestkit.NewMemArchive(),
			}
			if tc.withCoordinator {
				deps.Coordinator = leader.NewMySQL(db, discardLogger())
			}
			d, err := bootstrap.New(deps)
			require.NoError(t, err)

			assert.Equal(t, tc.want, d.ProcessorConcurrency())
		})
	}
}
