//go:build integration

// Idempotent re-processing (migration 00011). The detection processor nacks and re-claims a batch on a retryable detection miss
// (rulesapi.ErrProcessNotYetMaterialized), and a claim-lease-expiry re-offer can replay a stalled worker's events, so the SAME
// fork/exec events are folded through the builder more than once. Applying a batch twice MUST yield the identical process forest as
// applying it once: no duplicate generations, no fabricated re-exec rows, no phantom pid_reuse closes. Before the fix each replay
// duplicated rows (the processes table had only a surrogate PK), which cascaded into duplicate alerts because alert dedup keys on
// process_id. These tests pin the double-apply == single-apply invariant across the same state-machine cases the differential tests
// cover (fork/exec-case-b/re-exec/exec-without-fork/snapshot), reusing that harness's normalized-forest dump.

package tests

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// spec:server-process-graph-builder/re-processing-a-batch-is-idempotent/re-applying-the-same-batch-yields-the-same-forest
func TestProcessBatch_ReprocessingIsIdempotent(t *testing.T) {
	t.Parallel()
	b, _, db := twoBuilders(t)
	ctx := t.Context()
	base := int64(3_000_000_000)

	cases := []struct {
		name   string
		events []api.Event
	}{
		{"fork exec exit", []api.Event{forkEvt(base, 100, 1), execEvt(base+1, 100, 1, "/bin/a"), exitEvt(base+2, 100, 0)}},
		{"re-exec chain python sh bash", []api.Event{
			forkEvt(base, 200, 1), execEvt(base+1, 200, 1, "/usr/bin/python"),
			execEvt(base+2, 200, 1, "/bin/sh"), execEvt(base+3, 200, 1, "/bin/bash"),
		}},
		{"pid reuse", []api.Event{
			forkEvt(base, 300, 1), execEvt(base+1, 300, 1, "/bin/first"),
			forkEvt(base+2, 300, 9), execEvt(base+3, 300, 9, "/bin/second"),
		}},
		{"exec without fork", []api.Event{execEvt(base, 400, 1, "/bin/orphan")}},
		{"snapshot exec then heartbeat", []api.Event{
			snapExecEvt(base, 500, 1, "/Applications/Safari.app"), heartbeatEvt(base+1, 500),
		}},
		{"re-exec then pid reuse", []api.Event{
			forkEvt(base, 600, 1), execEvt(base+1, 600, 1, "/bin/a"), execEvt(base+2, 600, 1, "/bin/b"),
			forkEvt(base+3, 600, 9), execEvt(base+4, 600, 9, "/bin/c"),
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := "reproc-" + strconv.Itoa(i)
			events := rewriteHost(tc.events, host)

			require.NoError(t, b.ProcessBatch(ctx, events))
			once := dumpNormalizedForest(t, db, ctx, host)
			require.NotEmpty(t, once, "scenario must materialise at least one row so the assertion is meaningful")

			// Re-claim: fold the identical batch again. The preload now returns the first pass's committed rows, so every fork/exec
			// must be recognised (source_event_id / exec_event_id) as already-applied and skipped rather than duplicated.
			require.NoError(t, b.ProcessBatch(ctx, events))
			twice := dumpNormalizedForest(t, db, ctx, host)

			require.Equal(t, once, twice, "re-processing the batch must not change the process forest for %s", tc.name)
		})
	}
}

// TestProcessBatch_ReprocessingIsIdempotentProperty is the property-based form: for any random fork/exec/exit/snapshot/heartbeat
// sequence over a small PID space (the same generator the differential property test uses, where re-exec / PID-reuse /
// exec-without-fork collisions are frequent), applying the batch a second time leaves the forest unchanged.
func TestProcessBatch_ReprocessingIsIdempotentProperty(t *testing.T) {
	t.Parallel()
	b, _, db := twoBuilders(t)
	ctx := t.Context()
	iter := 0
	rapid.Check(t, func(rt *rapid.T) {
		iter++
		host := "reproc-pbt" + strconv.Itoa(iter)
		events := rewriteHost(genEventSequence(rt), host)

		require.NoError(t, b.ProcessBatch(ctx, events))
		once := dumpNormalizedForest(t, db, ctx, host)

		require.NoError(t, b.ProcessBatch(ctx, events))
		twice := dumpNormalizedForest(t, db, ctx, host)

		require.Equal(t, once, twice, "re-processing must be idempotent for the drawn sequence")
	})
}
