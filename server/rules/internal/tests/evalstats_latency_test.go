//go:build integration

package tests

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestMeasureEvalStatsRecordLatency is the measurement behind issue #837, kept in the tree rather than run once and pasted into a
// PR body, because the numbers it replaces were produced the wrong way and corrected in review: reciprocal throughput is not
// latency, and the distinction is the entire finding. Anyone re-checking the claim should be able to re-run it.
//
// Skipped unless EDR_MEASURE is set. It is a measurement, not an assertion: it has no pass condition beyond completing, so
// running it in CI would spend minutes to prove nothing.
//
//	EDR_MEASURE=1 EDR_TEST_DSN='root@tcp(127.0.0.1:33307)/edr_test?parseTime=true' \
//	  go test -tags integration -run TestMeasureEvalStatsRecordLatency -v ./server/rules/internal/detectionconfig/
//
// Deliberately NOT parallel, which is why paralleltest is silenced rather than satisfied: a latency measurement sharing the
// machine with the rest of the suite measures contention, not the thing it names. It is also skipped by default, so it costs the
// suite nothing.
//
//nolint:paralleltest // a measurement must have the machine to itself or its numbers mean nothing.
func TestMeasureEvalStatsRecordLatency(t *testing.T) {
	if os.Getenv("EDR_MEASURE") == "" { //nolint:forbidigo // a measurement gate, not wiring: the value selects whether to run at all.
		t.Skip("set EDR_MEASURE=1 to run the drain-path latency measurement")
	}

	db := full.Open(t)
	store := detectionconfig.NewStore(db)
	buffered := detectionconfig.NewBufferedEvalStats(store, nil)

	// 73 rules is what the dev server dispatches for one batch, which is the shape the original measurement used.
	batch := make(api.RuleEvalStats, 0, 73)
	for i := range 73 {
		batch = append(batch, api.RuleEvalStat{
			RuleID: fmt.Sprintf("measure_rule_%02d", i), Evaluations: 1, EvalNs: 1000, MaxEvalNs: 1000,
		})
	}

	measure := func(name string, writers int, rec api.RuleEvalStatsRecorder) {
		const perWriter = 40
		samples := make([][]time.Duration, writers)
		var wg sync.WaitGroup
		start := time.Now()
		for w := range writers {
			wg.Go(func() {
				mine := make([]time.Duration, 0, perWriter)
				for range perWriter {
					// Timed per CALL, which is the whole point: a p95 cannot be recovered from a total.
					callStart := time.Now()
					if err := rec.RecordRuleEvalStats(context.Background(), batch); err != nil {
						t.Errorf("%s: %v", name, err)
						return
					}
					mine = append(mine, time.Since(callStart))
				}
				samples[w] = mine
			})
		}
		wg.Wait()
		wall := time.Since(start)

		var all []time.Duration
		for _, s := range samples {
			all = append(all, s...)
		}
		slices.Sort(all)
		pct := func(p float64) time.Duration {
			if len(all) == 0 {
				return 0
			}
			idx := int(float64(len(all)-1) * p)
			return all[idx]
		}
		t.Logf("%-28s writers=%-3d calls=%-5d p50=%-10v p95=%-10v p99=%-10v wall=%v",
			name, writers, len(all), pct(0.50).Round(time.Microsecond), pct(0.95).Round(time.Microsecond),
			pct(0.99).Round(time.Microsecond), wall.Round(time.Millisecond))
	}

	for _, writers := range []int{1, 8, 32} {
		measure("store (before, per batch)", writers, store)
	}
	for _, writers := range []int{1, 8, 32} {
		measure("buffer (after, per batch)", writers, buffered)
	}

	// And what the buffer defers TO, so the saving is stated against a real cost rather than against zero.
	flushStart := time.Now()
	require.NoError(t, buffered.Flush(context.Background()))
	t.Logf("%-28s one flush of %d rules: %v", "flush (after, per interval)", 73, time.Since(flushStart).Round(time.Microsecond))
}
