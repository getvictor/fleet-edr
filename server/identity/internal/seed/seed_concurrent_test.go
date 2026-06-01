package seed_test

import (
	"sync"
	"testing"

	"log/slog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/seed"
)

// TestAdmin_ConcurrentBoot pins that the break-glass admin seed is safe when several replicas boot at once against a fresh
// database: every replica's seed must succeed and exactly one admin row must exist afterward. The race-safety is a property of
// users.Store.CreateBreakglass (INSERT ... ON DUPLICATE KEY UPDATE + re-read), so the loser of the create race gets the winner's
// row back with no error; this test guards that invariant at the seed.Admin level and would fail if CreateBreakglass regressed to
// a plain INSERT. The goroutines are released through a barrier so they hit the seed simultaneously, maximising the race window.
func TestAdmin_ConcurrentBoot(t *testing.T) {
	t.Parallel()
	t.Run("spec:server-availability/first-boot-admin-seed-is-safe-under-concurrent-replica-boot/two-replicas-seeding-concurrently-produce-exactly-one-admin-row", func(t *testing.T) {
		t.Parallel()
		us, rb, db := newSeedFixture(t)
		ctx := t.Context()

		const replicas = 8
		start := make(chan struct{})
		errs := make([]error, replicas)
		var wg sync.WaitGroup
		for i := range replicas {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start // release all goroutines together so they race on the create
				_, _, errs[i] = seed.Admin(ctx, us, rb, slog.Default(), nil)
			}(i)
		}
		close(start)
		wg.Wait()

		for i, err := range errs {
			require.NoErrorf(t, err, "replica %d seed must succeed under concurrent boot", i)
		}

		var n int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE email = ?`, seed.DefaultAdminEmail).Scan(&n))
		assert.Equalf(t, 1, n, "concurrent seed of %d replicas must produce exactly one admin row", replicas)
	})
}
