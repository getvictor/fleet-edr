package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"

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
		name        string
		concurrency int
		connBudget  int
		coordinator leader.Coordinator
		want        int
	}{
		{"non-positive concurrency floors to one worker", 0, 25, stubCoordinator{}, 1},
		{"the shipped default pool leaves the default worker count alone", 4, 25, stubCoordinator{}, 4},
		{"budget exactly the worker share leaves it alone", 4, 16, stubCoordinator{}, 4},
		{"tight budget clamps to the share the pool can serve", 8, 16, stubCoordinator{}, 4},
		{"a budget serving one worker's share clamps to one", 8, 4, stubCoordinator{}, 1},
		{"a budget below a full share still leaves one worker", 8, 3, stubCoordinator{}, 1},
		{"unknown budget skips the sizing", 8, 0, stubCoordinator{}, 8},
		{"no coordinator forces a single worker", 8, 25, nil, 1},
		{"a lockless single worker needs no pool share", 8, 2, nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:      discardLogger(),
				Batch:       10,
				Concurrency: tc.concurrency,
				Coordinator: tc.coordinator,
				ConnBudget:  tc.connBudget,
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
		name       string
		connBudget int
	}{
		{"a single-connection pool cannot hold a lock and claim at once", 1},
		{"a pool one short of a worker's needs is still a stall", connsPerWorker - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc, err := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:      discardLogger(),
				Batch:       10,
				Concurrency: 4,
				Coordinator: stubCoordinator{},
				ConnBudget:  tc.connBudget,
			})
			require.Error(t, err, "a pool that cannot serve one worker must not produce a processor")
			assert.Nil(t, proc)
			// The operator's next action is to raise the pool, so the error has to carry the number to raise it to.
			assert.Contains(t, err.Error(), "raise the pool to at least",
				"the refusal must tell the operator what to change, not just that something is wrong")
		})
	}
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
