package catchup_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/catchup"
)

// delivered is a command that carries the host's current state and is on its way, queued after the host enrolled: the case where
// nothing should be sent again. Each test below changes one thing about it, so what the case is testing is what differs.
func delivered(now time.Time) catchup.Latest {
	return catchup.Latest{Queued: true, Carries: true, CreatedAt: now.Add(-time.Hour), Status: catchup.StatusPending}
}

// spec:server-host-containment/a-host-is-owed-a-state-by-one-rule/a-host-that-never-received-the-state-is-sent-it
// spec:server-host-containment/a-host-is-owed-a-state-by-one-rule/a-host-that-reinstalled-is-sent-the-state-again
// spec:server-host-containment/a-host-is-owed-a-state-by-one-rule/a-failed-command-is-retried-only-after-a-bounded-wait
// spec:server-host-containment/a-host-is-owed-a-state-by-one-rule/a-status-the-version-does-not-recognize-is-left-alone
func TestNeeded(t *testing.T) {
	t.Parallel()
	now := time.Now()
	enrolledAt := now.Add(-2 * time.Hour)
	completedAt := func(ago time.Duration) *time.Time {
		at := now.Add(-ago)
		return &at
	}

	cases := []struct {
		name string
		cmd  func(c catchup.Latest) catchup.Latest
		want bool
	}{
		{"nothing was ever queued", func(c catchup.Latest) catchup.Latest { c.Queued = false; return c }, true},
		{"the queued command carries another state", func(c catchup.Latest) catchup.Latest { c.Carries = false; return c }, true},
		{"queued before the host enrolled", func(c catchup.Latest) catchup.Latest {
			c.CreatedAt = enrolledAt.Add(-time.Minute)
			return c
		}, true},
		{"queued at the moment the host enrolled", func(c catchup.Latest) catchup.Latest { c.CreatedAt = enrolledAt; return c }, true},
		{"expired", func(c catchup.Latest) catchup.Latest { c.Status = catchup.StatusExpired; return c }, true},
		{"cancelled", func(c catchup.Latest) catchup.Latest { c.Status = catchup.StatusCancelled; return c }, true},
		{"failed long enough ago", func(c catchup.Latest) catchup.Latest {
			c.Status, c.CompletedAt = catchup.StatusFailed, completedAt(catchup.FailedRetryAfter)
			return c
		}, true},
		{"failed recently", func(c catchup.Latest) catchup.Latest {
			c.Status, c.CompletedAt = catchup.StatusFailed, completedAt(catchup.FailedRetryAfter-time.Minute)
			return c
		}, false},
		{"failed with no completion time", func(c catchup.Latest) catchup.Latest {
			c.Status, c.CompletedAt = catchup.StatusFailed, nil
			return c
		}, false},
		{"pending", func(c catchup.Latest) catchup.Latest { c.Status = catchup.StatusPending; return c }, false},
		{"acked", func(c catchup.Latest) catchup.Latest { c.Status = catchup.StatusAcked; return c }, false},
		{"completed", func(c catchup.Latest) catchup.Latest { c.Status = catchup.StatusCompleted; return c }, false},
		// A status this version does not know was written by a newer one. Queueing against it would put a replica mid-upgrade in a
		// fight with the replica that wrote it, so it is left alone, and left alone whatever else this version thinks of the
		// command: the newer version's payload may be a shape this one reads as the wrong state, and it may have been queued
		// against an enrollment this one cannot see. Each of those, asked first, would resend.
		{"a status this version does not know", func(c catchup.Latest) catchup.Latest { c.Status = "quarantined"; return c }, false},
		{"an unknown status carrying what reads as another state", func(c catchup.Latest) catchup.Latest {
			c.Status, c.Carries = "quarantined", false
			return c
		}, false},
		{"an unknown status queued before the host enrolled", func(c catchup.Latest) catchup.Latest {
			c.Status, c.CreatedAt = "quarantined", enrolledAt.Add(-time.Minute)
			return c
		}, false},
		// A host that has never been sent one is resent whatever a newer version might know: there is no command to conflict with.
		{"nothing queued, whatever the status field holds", func(c catchup.Latest) catchup.Latest {
			c.Queued, c.Status = false, "quarantined"
			return c
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, catchup.Needed(tc.cmd(delivered(now)), enrolledAt, now))
		})
	}
}

// spec:server-host-containment/a-host-is-owed-a-state-by-one-rule/a-command-in-flight-is-left-alone
//
// The unchanged case, stated on its own so the table above is read as "this one thing differs" rather than as the whole contract.
func TestNeeded_LeavesADeliveredCommandAlone(t *testing.T) {
	t.Parallel()
	now := time.Now()
	assert.False(t, catchup.Needed(delivered(now), now.Add(-2*time.Hour), now))
}

func TestLoop_RunsUntilItsContextEnds(t *testing.T) {
	t.Parallel()
	var runs atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		catchup.Loop(ctx, "test", func(context.Context) (int, error) {
			runs.Add(1)
			return 0, nil
		}, time.Millisecond, nil)
	}()

	require.Eventually(t, func() bool { return runs.Load() >= 2 }, 5*time.Second, time.Millisecond, "the sweep runs every interval")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Loop did not return when its context ended")
	}
}

// A sweep that fails is logged and tried again rather than ending the loop: the next interval may find the database back.
func TestLoop_KeepsSweepingAfterAFailure(t *testing.T) {
	t.Parallel()
	var runs atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		catchup.Loop(ctx, "test", func(context.Context) (int, error) {
			runs.Add(1)
			return 0, errors.New("database unavailable")
		}, time.Millisecond, nil)
	}()

	require.Eventually(t, func() bool { return runs.Load() >= 3 }, 5*time.Second, time.Millisecond)
	cancel()
	<-done
}

// A zero or negative interval is the caller saying "the default", which production wiring relies on: cmd/main passes 0.
func TestLoop_TreatsANonPositiveIntervalAsTheDefault(t *testing.T) {
	t.Parallel()
	var runs atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		catchup.Loop(ctx, "test", func(context.Context) (int, error) {
			runs.Add(1)
			return 0, nil
		}, 0, nil)
	}()

	// Nothing should have run: the default interval is minutes, so a sweep inside this window would mean the zero was taken
	// literally and turned into a ticker that fires continuously.
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, runs.Load())
	cancel()
	<-done
}
