package graph

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec:server-process-graph-builder/exit-before-snapshot-exec-race-buffer/exit-arrives-without-a-matching-snapshot-exec-within-the-window
//
// Issue #176 named bug repro: an exit event whose UPDATE found no row gets buffered for pendingExitTTL; if no matching snapshot exec
// arrives within that window, the buffered exit is discarded so a recycled PID later cannot pick up the stale exit. Per repo
// guidance (CLAUDE.md test-style decision matrix), named bug repros are grouped as t.Run subtests under one parent so the bug
// number lives on the parent and the per-branch scenarios remain individually addressable.
//
// Pure-buffer test (no MySQL); the snapshot-exec-arrives-after-expiry branch in handleExec just reads from consumePendingExit, so
// pinning the buffer's expiry semantics here transitively pins the "fresh insert" half too.
func TestBuilder_PendingExit_Issue176(t *testing.T) {
	t.Parallel()

	t.Run("expires after TTL and is not inherited by a later recycled PID", func(t *testing.T) {
		t.Parallel()
		// Construct a Builder with a controllable clock. store=nil is safe because none of the buffer-management methods
		// (bufferPendingExit / consumePendingExit / sweepPendingExits) touch q.store: those calls live on the path that
		// goes through handleExec / handleExit's UPDATE round-trips.
		var (
			mu  sync.Mutex
			now = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
		)
		advance := func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(d)
		}
		clock := func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
		b := &Builder{
			logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			now:          clock,
			pendingExits: make(map[pendingExitKey]pendingExit),
		}

		// Phase 1: buffer an exit for (host-a, pid=1234). The buffer call stamps expiresAt at clock() + TTL.
		b.bufferPendingExit("host-a", 1234, pendingExit{
			exitTimeNs:       1_000_000_000,
			exitIngestedAtNs: 1_500_000_000,
			exitCode:         0,
			exitReason:       "kernel_exit",
		})
		require.Len(t, b.pendingExits, 1, "bufferPendingExit must insert one entry")

		// Phase 2: advance the clock just past pendingExitTTL and sweep. The map MUST shed the expired entry so the
		// buffer doesn't grow without bound across hours of no matching snapshot exec.
		advance(pendingExitTTL + time.Second)
		b.sweepPendingExits()
		assert.Empty(t, b.pendingExits, "sweepPendingExits MUST drop entries whose expiresAt has passed")

		// Phase 3: a "much later" snapshot exec for the SAME (host, pid) arrives. consumePendingExit MUST return ok=false so handleExec's
		// insertExecWithoutFork takes the no-pending-exit branch and the new row is inserted fresh without inheriting the long-expired
		// exit. This is the recycled-PID safety property the spec pins.
		advance(time.Hour) // an extreme delay to make the recycled-PID framing explicit
		_, ok := b.consumePendingExit("host-a", 1234)
		assert.False(t, ok, "consumePendingExit MUST NOT return an expired exit; a recycled PID must not inherit it")
	})

	t.Run("consumed before TTL elapses returns the buffered exit", func(t *testing.T) {
		t.Parallel()
		// Companion subtest: pins the issue #176 happy path (snapshot exec arrives within the window and picks up the buffered exit).
		// Without this probe, a regression that aggressively expires entries on every consumePendingExit call would slip through the
		// expiry subtest above (which only asserts the post-expiry side).
		var (
			mu  sync.Mutex
			now = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
		)
		clock := func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
		b := &Builder{
			logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			now:          clock,
			pendingExits: make(map[pendingExitKey]pendingExit),
		}

		b.bufferPendingExit("host-a", 7777, pendingExit{
			exitTimeNs:       2_000_000_000,
			exitIngestedAtNs: 2_500_000_000,
			exitCode:         15,
			exitReason:       "kernel_signal",
		})
		pe, ok := b.consumePendingExit("host-a", 7777)
		require.True(t, ok, "consumePendingExit MUST return the just-buffered exit while still within the TTL window")
		assert.Equal(t, int64(2_000_000_000), pe.exitTimeNs, "consumed exit must carry the buffered exitTimeNs")
		assert.Equal(t, 15, pe.exitCode, "consumed exit must carry the buffered exitCode")
		assert.Empty(t, b.pendingExits, "consumePendingExit MUST remove the entry on read")
	})
}
