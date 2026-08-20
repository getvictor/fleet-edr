package pipeline

import (
	"context"
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

// The clamp is what keeps the per-host lock from deadlocking the pool: a worker in its critical section holds two connections, so a
// pool that cannot serve two per worker would leave every worker holding a lock connection and waiting for a claim connection.
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
		{"budget above twice the worker count leaves it alone", 4, 25, stubCoordinator{}, 4},
		{"budget exactly twice the worker count leaves it alone", 4, 8, stubCoordinator{}, 4},
		{"tight budget clamps to what the pool can serve", 8, 4, stubCoordinator{}, 2},
		{"a budget below one worker's needs still leaves one worker", 8, 1, stubCoordinator{}, 1},
		{"unknown budget skips the clamp", 8, 0, stubCoordinator{}, 8},
		{"no coordinator forces a single worker", 8, 25, nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proc := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:      discardLogger(),
				Batch:       10,
				Concurrency: tc.concurrency,
				Coordinator: tc.coordinator,
				ConnBudget:  tc.connBudget,
			})
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

// A non-positive batch would spin the drain loop, since an empty claim returns 0 and 0 >= 0 never breaks.
func TestNewProcessor_BatchFloorsToOne(t *testing.T) {
	t.Parallel()
	proc := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{Logger: discardLogger(), Batch: 0})
	assert.Equal(t, 1, proc.batch)
}

// GET_LOCK rejects a name over 64 characters outright rather than truncating it, so a long host id must hash rather than strand its
// backlog behind a lock that can never be taken.
func TestHostClaimLockName(t *testing.T) {
	t.Parallel()

	short := hostClaimLockName("F1E2D3C4-0000-1111-2222-333344445555")
	assert.Equal(t, hostClaimLockPrefix+"F1E2D3C4-0000-1111-2222-333344445555", short,
		"an enrollment-sized host id stays readable in performance_schema.metadata_locks")
	assert.LessOrEqual(t, len(short), mysqlLockNameMax)

	long := strings.Repeat("h", 300)
	hashed := hostClaimLockName(long)
	assert.Len(t, hashed, mysqlLockNameMax, "an over-long name must be hashed down to the limit, not passed through")
	assert.True(t, strings.HasPrefix(hashed, hostClaimLockPrefix), "the namespace prefix survives hashing")
	assert.NotEqual(t, hashed, hostClaimLockName(long+"x"), "distinct hosts must not collapse onto one lock")
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
			proc := NewProcessor(&scriptedEventLog{}, nil, nil, ProcessorOptions{
				Logger:      discardLogger(),
				Batch:       10,
				Concurrency: tc.concurrency,
				Coordinator: stubCoordinator{},
			})
			assert.Equal(t, tc.want, proc.hostCandidates())
		})
	}
}
