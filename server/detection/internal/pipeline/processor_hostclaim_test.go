package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/coordination/leader"
)

// stubCoordinator is a non-nil leader.Coordinator that never runs anything. NewProcessor only checks whether a coordinator is present,
// so the clamp tests need presence, not behaviour.
type stubCoordinator struct{}

func (stubCoordinator) RunIfLeader(context.Context, string, func(context.Context) error) error {
	return nil
}

func (stubCoordinator) DoOnceIfLeader(context.Context, string, func(context.Context) error) (bool, error) {
	return false, nil
}

func (stubCoordinator) WithLock(context.Context, string, func(context.Context) error) error {
	return nil
}

func (stubCoordinator) Lock(context.Context, string) (func(), error) { return func() {}, nil }

// releaseRecordingCoordinator runs the locked callback and records what the event log had been told by the time the callback returns,
// which is the instant the advisory lock is released. That is the only way to observe lock scope from outside: DoOnceIfLeader owns the
// lock's lifetime, so "inside the lock" means "before this callback returned".
type releaseRecordingCoordinator struct {
	nackedAtRelease []string
	log             *scriptedEventLog
}

func (c *releaseRecordingCoordinator) DoOnceIfLeader(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
	err := fn(ctx)
	c.nackedAtRelease = append([]string(nil), c.log.nacked...)
	return true, err
}

func (c *releaseRecordingCoordinator) RunIfLeader(context.Context, string, func(context.Context) error) error {
	return nil
}
func (c *releaseRecordingCoordinator) WithLock(context.Context, string, func(context.Context) error) error {
	return nil
}
func (c *releaseRecordingCoordinator) Lock(context.Context, string) (func(), error) {
	return func() {}, nil
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-failed-batch-is-requeued-before-the-host-is-released
//
// A failed batch must be requeued INSIDE the host lock. Requeueing after the lock is released opens a window in which the next
// claimer takes that host's LATER events and folds them ahead of the earlier ones still awaiting their Nack, which is the same
// causal-order violation the per-host lock exists to prevent, just reached by the failure path instead of the happy path.
func TestProcessor_FailedBatchIsRequeuedInsideTheHostLock(t *testing.T) {
	t.Parallel()

	log := &scriptedEventLog{batch: oneEventBatch()}
	coordinator := &releaseRecordingCoordinator{log: log}
	proc, err := NewProcessor(log, stubBuilder{err: errors.New("graph write failed")}, stubEvaluator{}, ProcessorOptions{
		Logger:      discardLogger(),
		Batch:       1,
		Concurrency: 1,
		Coordinator: coordinator,
	})
	require.NoError(t, err)

	proc.ProcessOnce(context.Background())

	require.Equal(t, []string{"evt-1"}, log.nacked, "a builder failure requeues the batch")
	assert.Equal(t, []string{"evt-1"}, coordinator.nackedAtRelease,
		"the Nack must already have landed when the host lock is released, or the next claimer can fold past the retried events")
	assert.Empty(t, log.acked, "a failed batch is never acked")
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/worker-count-is-bounded-by-the-connection-pool
//
// Sizing the fleet to the pool is what keeps the per-host lock from deadlocking it: a worker in its critical section holds two
// connections, so a pool that cannot serve two per worker would leave every worker holding a lock connection and waiting for a claim
// connection. The budget is the whole process-wide pool, so the workers get a share of it rather than all of it.
func TestNewProcessor_ConcurrencyBounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		concurrency   int
		connBudget    int
		reservedConns int
		coordinator   leader.Coordinator
		want          int
	}{
		{"non-positive concurrency floors to one worker", 0, 25, 0, stubCoordinator{}, 1},
		{"the shipped default pool leaves the default worker count alone", 4, 25, 0, stubCoordinator{}, 4},
		// The production shape, and the case this must never regress: reserving the leader loops out of the real pool still has
		// to leave the configured fleet intact, or the fix for issue #722 would quietly shrink every deployment.
		{"spec:server-availability/worker-sizing-counts-only-connections-that-can-actually-be-obtained/reserving-the-long-lived-holders-does-not-shrink-a-healthy-deployment", 4, 25, LeaderGatedConns(true, true), stubCoordinator{}, 4},
		{"budget exactly the worker share leaves it alone", 4, 16, 0, stubCoordinator{}, 4},
		{"tight budget clamps to the share the pool can serve", 8, 16, 0, stubCoordinator{}, 4},
		{"a budget serving one worker's share clamps to one", 8, 4, 0, stubCoordinator{}, 1},
		// The reservation is subtracted BEFORE sizing: 16 looks like 4 workers, but 8 of it is already pinned for the whole
		// process lifetime and is never coming back.
		{"reserved connections are not available to workers", 8, 16, 8, stubCoordinator{}, 2},
		{"unknown budget skips the sizing", 8, 0, 0, stubCoordinator{}, 8},
		{"no coordinator forces a single worker", 8, 25, 0, nil, 1},
		{"a lockless single worker needs no pool share", 8, 2, 0, nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:        discardLogger(),
				Batch:         10,
				Concurrency:   tc.concurrency,
				Coordinator:   tc.coordinator,
				ConnBudget:    tc.connBudget,
				ReservedConns: tc.reservedConns,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, proc.concurrency)
			// Run logs the reduction so an operator can see the configured count was not honored; the record has to exist whenever a
			// reduction happened, and must not exist otherwise.
			if tc.want < tc.concurrency {
				require.NotNil(t, proc.clamp, "a reduced worker count must carry a reason to log")
				assert.NotEmpty(t, proc.clamp.reason)
			} else {
				assert.Nil(t, proc.clamp, "an honored worker count must not log a reduction")
			}
		})
	}
}

// spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/a-pool-too-small-for-one-worker-is-refused-at-startup
//
// A pool too small for even one worker cannot be rescued by running fewer workers: the last worker standing still pins one connection
// for GET_LOCK and then waits forever for a claim connection on an empty pool. Silently clamping to one worker there would preserve
// the very stall the sizing exists to prevent, so construction must fail and name the pool size the deployment needs.
func TestNewProcessor_RefusesPoolBelowOneWorker(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		connBudget    int
		reservedConns int
	}{
		{"a single-connection pool cannot hold a lock and claim at once", 1, 0},
		{"a pool one short of a worker's needs is still a stall", connsPerWorker - 1, 0},
		// These two used to be ADMITTED by a guard whose own error message called them insufficient: it refused below
		// connsPerWorker (2) while telling the operator to raise the pool to 4, then clamped 2 and 3 to a worker that could not
		// make progress. A guard must not accept a value its message rejects (issue #722).
		{"spec:server-availability/worker-sizing-counts-only-connections-that-can-actually-be-obtained/a-budget-the-guard-s-own-advice-rejects-is-refused-rather-than-reduced", connsPerWorker, 0},
		{"one short of a full worker share is refused too", minConnsForOneWorker - 1, 0},
		// Room for the leader loops but not for a worker afterwards. Before the reservation existed this looked like a healthy
		// pool and produced a fleet that would stall on its first claim.
		{"spec:server-availability/worker-sizing-counts-only-connections-that-can-actually-be-obtained/a-pool-with-room-for-the-sweeps-but-not-for-a-worker-is-refused", LeaderGatedConns(true, true) + 1, LeaderGatedConns(true, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:        discardLogger(),
				Batch:         10,
				Concurrency:   4,
				Coordinator:   stubCoordinator{},
				ConnBudget:    tc.connBudget,
				ReservedConns: tc.reservedConns,
			})
			require.Error(t, err, "a pool that cannot serve one worker must not produce a processor")
			assert.Nil(t, proc)
			// The operator's next action is to raise the pool, so the error has to carry the number to raise it to, and that
			// number has to be the one the guard actually enforces. The two disagreeing is what let 2 and 3 through.
			assert.Contains(t, err.Error(), "raise the pool to at least",
				"the refusal must tell the operator what to change, not just that something is wrong")
			assert.Contains(t, err.Error(), fmt.Sprintf("at least %d", tc.reservedConns+minConnsForOneWorker),
				"the advertised threshold must be the one enforced, reservation included")
		})
	}
}

// TestLeaderGatedConnsMatchesWhatRunStarts pins the connection reservation against the loops Run ACTUALLY starts, by watching the
// coordinator rather than by comparing one hand-maintained list to another.
//
// The first version of this test compared LeaderGatedConns to a literal slice of the three lock names, which Copilot correctly
// pointed out cannot catch the drift it claims to: adding a fourth gated loop while leaving both the constant and that slice
// untouched passes it. Observing the coordinator is the difference, because a fourth loop calls RunIfLeader and is counted here
// whether or not anyone remembered to update a list.
//
// The reservation matters because a running gated loop holds its lock, and therefore a pooled connection, for the process lifetime.
// Under-count it and the processor sizes its fleet against connections that never come back (issue #722).
func TestLeaderGatedConnsMatchesWhatRunStarts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		processTTLEnabled bool
		retentionEnabled  bool
	}{
		{"all sweeps enabled", true, true},
		{"process-ttl disabled", false, true},
		{"retention disabled", true, false},
		{"only queue-prune", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			coord := &recordingCoordinator{}
			// Built as struct literals rather than through the constructors: this test is in-package, and the constructors
			// validate stores it has no use for. What Run cares about is only that the pointers are non-nil.
			r := NewRunner(RunnerOptions{
				ProcessTTL:  &ProcessTTLRunner{maxAge: enabledDuration(tc.processTTLEnabled)},
				Retention:   &RetentionRunner{retentionDays: boolToDays(tc.retentionEnabled)},
				QueuePrune:  &QueuePruneRunner{},
				Coordinator: coord,
			})

			// Run returns once every loop has; a cancelled context stops them all promptly.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.NoError(t, r.Run(ctx))

			// Every gated loop Run started took a distinct lock, whether or not its sweep was enabled: the gating happens outside
			// the runner, so the count of GATED loops is always the full set. What LeaderGatedConns reports is narrower, the ones
			// that HOLD their lock, so the assertion is that it never over-counts what Run started.
			started := coord.lockCount()
			reserved := LeaderGatedConns(tc.processTTLEnabled, tc.retentionEnabled)
			assert.LessOrEqual(t, reserved, started,
				"the reservation must never exceed the loops that exist, or it would refuse pools that are adequate")
			assert.Equal(t, leaderGatedLoops, started,
				"Run starts one gated loop per lock name; a new one added without updating leaderGatedLoops fails here")
		})
	}
}

// recordingCoordinator counts the distinct locks RunIfLeader was asked for, which is how the test above observes Run's real gated
// call sites instead of a list someone has to remember to update.
type recordingCoordinator struct {
	mu    sync.Mutex
	locks map[string]struct{}
}

// RunIfLeader records the lock and deliberately does NOT run fn. The question this test asks is which locks Run takes, not what the
// sweeps do once they hold one, and running them would drag their stores and tickers into a test about connection accounting.
func (c *recordingCoordinator) RunIfLeader(_ context.Context, lockName string, _ func(context.Context) error) error {
	c.mu.Lock()
	if c.locks == nil {
		c.locks = map[string]struct{}{}
	}
	c.locks[lockName] = struct{}{}
	c.mu.Unlock()
	return nil
}

func (c *recordingCoordinator) lockCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.locks)
}

func (*recordingCoordinator) DoOnceIfLeader(context.Context, string, func(context.Context) error) (bool, error) {
	return false, nil
}
func (*recordingCoordinator) WithLock(context.Context, string, func(context.Context) error) error {
	return nil
}
func (*recordingCoordinator) Lock(context.Context, string) (func(), error) {
	return func() {}, nil
}

func enabledDuration(on bool) time.Duration {
	if on {
		return time.Hour
	}
	return 0
}

func boolToDays(on bool) int {
	if on {
		return 30
	}
	return 0
}

// A non-positive batch would spin the drain loop, since an empty claim returns 0 and 0 >= 0 never breaks.
func TestNewProcessor_BatchFloorsToOne(t *testing.T) {
	t.Parallel()
	proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{Logger: discardLogger(), Batch: 0})
	require.NoError(t, err)
	assert.Equal(t, 1, proc.batch)
}

// GET_LOCK rejects a name over 64 characters outright rather than truncating it, so a long host id must hash rather than strand its
// backlog behind a lock that can never be taken.
func TestHostClaimLockName(t *testing.T) {
	t.Parallel()

	t.Run("an enrollment-sized host id passes through readable", func(t *testing.T) {
		t.Parallel()
		name := hostClaimLockName("F1E2D3C4-0000-1111-2222-333344445555")
		assert.Equal(t, hostClaimLockPrefix+"F1E2D3C4-0000-1111-2222-333344445555", name,
			"an enrollment-sized host id stays readable in performance_schema.metadata_locks")
		assert.LessOrEqual(t, len(name), mysqlLockNameMax)
	})

	t.Run("an over-long host id hashes down to the limit", func(t *testing.T) {
		t.Parallel()
		hashed := hostClaimLockName(strings.Repeat("h", 300))
		assert.Len(t, hashed, mysqlLockNameMax, "an over-long name must be hashed down to the limit, not passed through")
		assert.True(t, strings.HasPrefix(hashed, hostClaimLockPrefix), "the namespace prefix survives hashing")
	})

	t.Run("hashed names stay distinct per host", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("h", 300)
		assert.NotEqual(t, hostClaimLockName(long), hostClaimLockName(long+"x"),
			"distinct hosts must not collapse onto one lock")
	})
}

// The candidate window is what lets a worker step over a host another worker holds instead of queueing behind it.
func TestHostCandidatesWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		concurrency int
		want        int
	}{
		{"single worker still looks past one blocked host", 1, minHostCandidates},
		{"the window scales with the worker count", 4, 4 * hostCandidateFactor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:      discardLogger(),
				Batch:       10,
				Concurrency: tc.concurrency,
				Coordinator: stubCoordinator{},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, proc.hostCandidates())
		})
	}
}

// lostLockCoordinator reports that it acquired the host lock, ran the callback, and then discovered the lock had gone: the shape
// leader.DoOnceIfLeader returns after issue #721 when the connection holding the lock dies mid-callback.
type lostLockCoordinator struct {
	stubCoordinator
	ran atomic.Bool
}

func (c *lostLockCoordinator) DoOnceIfLeader(ctx context.Context, _ string, fn func(context.Context) error) (bool, error) {
	c.ran.Store(true)
	// The callback DOES run, which is the whole difficulty: work may have been partially done before the lock went.
	if err := fn(ctx); err != nil {
		return true, err
	}
	return true, leader.ErrLockLost
}

// TestProcessHostTreatsALostLockAsNotRun pins how the processor handles a host whose claim lock went while it was working
// (issue #721's ErrLockLost, reaching the processor through the per-host claim added in #717).
//
// Reporting "did not run" is right even though the callback did run: nothing is acknowledged until a batch completes, so the events
// stay in flight and are redelivered when the claim lease expires. What must not happen is the worker treating it as a completed
// batch and draining on, which would leave a host's events folded by two claimers.
func TestProcessHostTreatsALostLockAsNotRun(t *testing.T) {
	t.Parallel()
	coord := &lostLockCoordinator{}
	proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
		Logger:      discardLogger(),
		Batch:       10,
		Concurrency: 1,
		Coordinator: coord,
		ConnBudget:  25,
	})
	require.NoError(t, err)

	claimed, ran := proc.processHost(context.Background(), "host-a")

	assert.True(t, coord.ran.Load(), "the coordinator did hand the callback the lock before losing it")
	assert.False(t, ran, "a lost lock must not read as a completed batch; the worker has to move to another host")
	assert.Zero(t, claimed, "and it must not report progress it cannot vouch for")
}
