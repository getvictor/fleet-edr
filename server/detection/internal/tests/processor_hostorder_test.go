//go:build integration

// Per-host ordering coverage for issue #717. The graph builder resolves each exec against the rows already flushed, so a pid's fork
// must reach it before that pid's exec. Before #717 the queue claim spanned hosts and SKIP LOCKED handed concurrent workers an
// interleaved split of one host's stream, so an exec was folded while its fork sat unflushed in another worker's batch: the builder
// took the exec-without-fork path and wrote a duplicate row with a fabricated fork_time_ns, no previous_exec_id, and an orphaned fork
// row carrying a wrong inherited path.
//
// The processor now serializes each host on that host's advisory lock, so these tests assert the property the old
// TestProcessor_IntraReplicaConcurrencyDrainsCompletely deliberately could not: it seeds only independent forks, whose forest is the
// same under any ordering, which is precisely why this defect went unnoticed.
//
// Note on lock scope: MySQL advisory locks are keyed per SERVER, not per database, so the per-test database that full.Open hands out
// does NOT isolate lock names. Host ids here are derived from the test name so a parallel sibling test cannot contend on the same
// per-host lock.

package tests

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/coordination/leader"
	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

// queueRig is one database carrying both the visibility queue and the detection graph, which is the production shape: the processor
// claims from the queue and writes the forest through the same handle.
type queueRig struct {
	db       *sqlx.DB
	eventLog visibilityapi.EventLog
	builder  *graph.Builder
}

func newQueueRig(t *testing.T) *queueRig {
	t.Helper()
	db := full.Open(t)
	// A worker inside its per-host critical section holds TWO connections: the one GET_LOCK pins and the one its claim and flush run
	// on, and the processor only sizes a worker fleet to a SHARE of the pool because production shares it with the request path. The
	// suite's default 4-connection pool would therefore clamp a 4-worker fleet down to one, which is not the configuration these tests
	// mean to exercise, and would park the gated test on its own assertion queries. Sixteen is the smallest budget that leaves four
	// workers intact, is well inside the suite's headroom (max-connections=500), and matches the production shape where MaxOpenConns
	// sits far above the fleet's needs.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	require.NoError(t, vis.ApplySchema(t.Context()), "apply visibility schema")
	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	return &queueRig{db: db, eventLog: vis.EventLog(), builder: graph.NewBuilder(store, discardLogger())}
}

// orderSensitiveEvents is a stream whose forest depends on fold order: each child pid forks, execs, re-execs, and exits, and every
// child is a child of 600 so the fork's inherited path depends on the parent's row already existing. Applied in order this yields one
// row per generation with the re-exec linked and the prior generation closed; applied out of order it yields duplicate rows with
// fabricated fork times and NULL back-references. childPIDs sizes the stream: each child adds one more fork/exec adjacency that an
// unserialized fleet can split, so a test that wants a split to be near-certain rather than merely possible passes more of them.
func orderSensitiveEvents(hostID string, base int64, childPIDs ...int) []api.Event {
	return retagEvents(orderSensitiveTemplate(base, childPIDs...), hostID)
}

// retagEvents rewrites both the host and the event ids. The queue's primary key is event_id alone, and the terse builders derive ids
// from timestamps, so two hosts seeded from one template would collide and Append's idempotent INSERT IGNORE would silently drop the
// second host's events. Rewriting the ids keeps the timestamps identical, which the forest comparison depends on.
func retagEvents(events []api.Event, hostID string) []api.Event {
	out := rewriteHost(events, hostID)
	for i := range out {
		out[i].EventID = hostID + "-" + out[i].EventID
	}
	return out
}

func orderSensitiveTemplate(base int64, childPIDs ...int) []api.Event {
	events := []api.Event{
		forkEvt(base, 600, 1),
		execEvt(base+10, 600, 1, "/opt/homebrew/bin/python3"),
	}
	for i, pid := range childPIDs {
		start := base + int64(100*(i+1))
		events = append(events,
			forkEvt(start, pid, 600),
			execEvt(start+10, pid, 600, "/bin/zsh"),
			execEvt(start+20, pid, 600, "/usr/bin/curl"),
			exitEvt(start+30, pid, 0),
		)
	}
	return events
}

// drainQueue runs a processor with the given worker count until the queue is empty, then stops it. It fails the test if the drain or
// the shutdown does not complete, so a stuck host lock surfaces here rather than as a mysterious empty forest later.
func drainQueue(t *testing.T, rig *queueRig, workers int, batch int, coordinator leader.Coordinator) {
	t.Helper()
	ctx := t.Context()
	proc, err := pipeline.NewProcessor(rig.eventLog, rig.builder, nil, pipeline.ProcessorOptions{
		Logger:      discardLogger(),
		Interval:    2 * time.Millisecond,
		Batch:       batch,
		Concurrency: workers,
		Coordinator: coordinator,
		ConnBudget:  rig.db.Stats().MaxOpenConnections,
	})
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = proc.Run(runCtx)
		close(done)
	}()
	require.Eventually(t, func() bool {
		pending, err := rig.eventLog.CountPending(ctx)
		return err == nil && pending == 0
	}, 30*time.Second, 10*time.Millisecond, "the worker fleet must drain the queue")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("processor did not stop within 5s of cancel")
	}
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/events-for-one-host-are-folded-in-causal-order-under-concurrency
//
// The equivalence property: concurrent workers must produce the same forest a single worker produces. Batch size 1 is the sharpest
// setting for it, because every event is then its own claim and a fleet with no per-host serialization is guaranteed to interleave
// one host's stream rather than merely likely to.
func TestProcessor_ConcurrentWorkersMatchSingleWorkerForest(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	rig := newQueueRig(t)
	base := time.Now().UnixNano()

	// Host ids carry the test name so a parallel sibling cannot collide on the server-scoped advisory lock.
	concurrentHost := fmt.Sprintf("order-conc-%s", t.Name())
	singleHost := fmt.Sprintf("order-seq-%s", t.Name())

	// Ten children, so the stream carries ten order-sensitive fork/exec adjacencies rather than two. The property holds at any width;
	// the width is what makes the test a reliable DETECTOR, since four unserialized workers claiming one event at a time would have to
	// get every one of the ten pairs right by chance to pass.
	children := []int{601, 602, 603, 604, 605, 606, 607, 608, 609, 610}

	require.NoError(t, rig.eventLog.Append(ctx, orderSensitiveEvents(concurrentHost, base, children...)))
	drainQueue(t, rig, 4, 1, leader.NewMySQL(rig.db, discardLogger()))

	require.NoError(t, rig.eventLog.Append(ctx, orderSensitiveEvents(singleHost, base, children...)))
	drainQueue(t, rig, 1, 1, leader.NewMySQL(rig.db, discardLogger()))

	concurrent := dumpNormalizedForest(t, rig.db, ctx, concurrentHost)
	single := dumpNormalizedForest(t, rig.db, ctx, singleHost)

	require.NotEmpty(t, single, "the single-worker reference must have materialized a forest")
	require.Equal(t, single, concurrent,
		"four workers must fold one host's stream into the same forest a single worker does: a difference here is the #717 split")
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/events-for-one-host-are-folded-in-causal-order-under-concurrency
//
// The shape assertions behind the equivalence above, stated directly so a regression reads as the defect rather than as an opaque
// forest diff: one row per generation, the re-exec linked to the image it replaced, the prior generation closed, and no exec row whose
// fork_time_ns was fabricated from its own exec timestamp.
func TestProcessor_ConcurrentWorkersLinkReExecChains(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	rig := newQueueRig(t)
	host := fmt.Sprintf("order-shape-%s", t.Name())

	require.NoError(t, rig.eventLog.Append(ctx, orderSensitiveEvents(host, time.Now().UnixNano(), 601, 602)))
	drainQueue(t, rig, 4, 1, leader.NewMySQL(rig.db, discardLogger()))

	var rows int
	require.NoError(t, rig.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = ?`, host).Scan(&rows))
	// 600 contributes one row (fork then exec, folded in place); 601 and 602 each contribute two generations.
	assert.Equal(t, 5, rows, "one row per generation, no duplicates from an exec folded before its fork")

	var linked int
	require.NoError(t, rig.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = ? AND previous_exec_id IS NOT NULL`, host).Scan(&linked))
	assert.Equal(t, 2, linked, "each re-exec links to the generation it replaced")

	var fabricated int
	require.NoError(t, rig.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = ? AND exec_time_ns IS NOT NULL AND exec_time_ns = fork_time_ns`,
		host).Scan(&fabricated))
	assert.Zero(t, fabricated, "no generation may take its fork time from its own exec timestamp")

	var closed int
	require.NoError(t, rig.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE host_id = ? AND exit_time_ns IS NOT NULL`, host).Scan(&closed))
	assert.Equal(t, 4, closed, "each re-exec closes its prior generation, and each pid's exit closes the live one")
}

// gatedBuilder blocks the first batch it sees for gateHost until release is closed, so a test can hold one host's lock open and watch
// whether other hosts keep moving.
//
// Every worker in the fleet calls ProcessBatch concurrently, so the gate needs its own synchronization: the per-host lock serializes
// the gated host's batches against each other but says nothing about the free host's batches running at the same time. sync.Once
// carries the "already gated" state instead of a plain bool, and the host is compared BEFORE the gate is touched so a free-host batch
// never reads state a gated-host batch is writing.
type gatedBuilder struct {
	inner    *graph.Builder
	gateHost string
	entered  chan struct{}
	release  chan struct{}
	gate     sync.Once
}

func (g *gatedBuilder) ProcessBatch(ctx context.Context, events []visibilityapi.Event) error {
	if len(events) > 0 && events[0].HostID == g.gateHost {
		g.gate.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	return g.inner.ProcessBatch(ctx, events)
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/serializing-one-host-does-not-stall-the-others
//
// Serializing per host must not serialize the fleet. A worker parked inside one host's critical section holds only that host's lock,
// so another worker has to make progress on a different host meanwhile. Asserted on observed progress, never on wall-clock timing,
// which would be flaky on a loaded CI runner.
func TestProcessor_HeldHostLockDoesNotStallOtherHosts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	rig := newQueueRig(t)
	base := time.Now().UnixNano()

	blocked := fmt.Sprintf("gate-blocked-%s", t.Name())
	free := fmt.Sprintf("gate-free-%s", t.Name())
	// Only the blocked host is queued up front. Queueing the free host too would let it finish BEFORE a worker ever entered the gate,
	// and the progress assertion below would then pass without a lock ever being held: it would be satisfied by work that happened
	// while nothing was blocked. Appending it after the gate trips makes the assertion unambiguous, because the free host's work did
	// not exist until a worker was already parked inside the blocked host's critical section.
	require.NoError(t, rig.eventLog.Append(ctx, orderSensitiveEvents(blocked, base, 601, 602)))

	gated := &gatedBuilder{inner: rig.builder, gateHost: blocked, entered: make(chan struct{}), release: make(chan struct{})}
	proc, err := pipeline.NewProcessor(rig.eventLog, gated, nil, pipeline.ProcessorOptions{
		Logger:      discardLogger(),
		Interval:    2 * time.Millisecond,
		Batch:       1,
		Concurrency: 4,
		Coordinator: leader.NewMySQL(rig.db, discardLogger()),
		ConnBudget:  rig.db.Stats().MaxOpenConnections,
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
		case <-time.After(5 * time.Second):
			t.Errorf("processor did not stop within 5s of cancel")
		}
	})

	select {
	case <-gated.entered:
	case <-time.After(20 * time.Second):
		t.Fatalf("no worker entered the gated host's batch")
	}

	// A worker is now parked inside the blocked host's critical section, holding that host's lock. Everything the free host does from
	// here happens while that lock is held.
	require.NoError(t, rig.eventLog.Append(ctx, orderSensitiveEvents(free, base, 601, 602)))

	// The blocked host is parked mid-flush. The free host must still drain to completion.
	freeCount := func() int {
		var n int
		require.NoError(t, rig.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM processes WHERE host_id = ?`, free).Scan(&n))
		return n
	}
	require.Eventually(t, freeEventuallyComplete(freeCount), 25*time.Second, 20*time.Millisecond,
		"a worker holding one host's lock must not stop another worker from finishing a different host")

	close(gated.release)
	require.Eventually(t, func() bool {
		pending, err := rig.eventLog.CountPending(ctx)
		return err == nil && pending == 0
	}, 25*time.Second, 20*time.Millisecond, "the gated host drains once released")
}

// freeEventuallyComplete adapts the row counter to require.Eventually: the ungated host's five generations are all materialized.
func freeEventuallyComplete(count func() int) func() bool {
	return func() bool { return count() == 5 }
}
