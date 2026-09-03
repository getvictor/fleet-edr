package catalog

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-graph-outage-stops-the-batch-rather-than-repeating-the-failing-read
//
// TestPendingMiss_AbsorbPropagatesGraphUnavailable pins the amplification bound, which the first cut of #798 removed by accident.
//
// absorb continues the batch past a retryable per-event miss on purpose (issue #661: one permanently orphaned event must not mask
// every other event behind it). A failed graph READ is not that condition. Every remaining read in the batch will fail identically,
// so continuing turns one outage into a read per event per rule, on every retry, for as long as the queue keeps re-offering the
// batch: load on a database that is already in trouble, which delays the recovery the retry is waiting for.
//
// This is what absorb's own comment always claimed ("retrying the remaining events against a broken reader would just multiply the
// failure"). Routing read failures through the generic retry sentinel quietly made the code stop matching it.
func TestPendingMiss_AbsorbPropagatesGraphUnavailable(t *testing.T) {
	t.Parallel()

	t.Run("a failed graph read is propagated, not absorbed", func(t *testing.T) {
		t.Parallel()
		var p pendingMiss
		readErr := fmt.Errorf("graph read GetExecChain: connection refused: %w", api.ErrGraphUnavailable)

		got := p.absorb(readErr)

		require.Error(t, got, "the caller must stop the batch rather than keep reading against a failed dependency")
		require.ErrorIs(t, got, api.ErrGraphUnavailable)
		require.NoError(t, p.err, "and it must not be parked as a per-event miss, which is what would continue the loop")
	})

	t.Run("an ordinary retryable miss is still absorbed", func(t *testing.T) {
		t.Parallel()
		var p pendingMiss
		miss := fmt.Errorf("pid 42: %w", api.ErrProcessNotYetMaterialized)

		got := p.absorb(miss)

		require.NoError(t, got, "issue #661: one undecidable event must not mask the rest of the batch")
		require.ErrorIs(t, p.err, api.ErrProcessNotYetMaterialized, "it is remembered and reported after the loop")
	})
}
