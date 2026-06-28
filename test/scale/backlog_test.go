package scale

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAggregateServerBacklog pins the pure aggregation + gate over a sampled-depth set, with no DB. The sampler that produces the
// samples is exercised live by the long-form lane (it needs a real MySQL); these cases pin the percentile wiring and the gate
// decision, including that the gate composes after the ingest gates (only ever flips Pass to false).
func TestAggregateServerBacklog(t *testing.T) {
	t.Parallel()

	t.Run("records percentiles and leaves Pass untouched when the gate is disabled", func(t *testing.T) {
		t.Parallel()
		rep := &Report{Pass: true}
		samples := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
		aggregateServerBacklog(rep, samples, Options{PassMaxServerBacklog: 0})
		assert.True(t, rep.Pass, "a disabled gate (0) never fails the run")
		assert.Equal(t, 10, rep.ServerBacklogSamples)
		assert.Equal(t, int64(100), rep.ServerBacklogMax)
		assert.Equal(t, int64(60), rep.ServerBacklogP50, "nearest-rank p50 (rank=ceil(.5*10)+0.5 -> index 5) of 10..100 by tens")
		assert.Equal(t, int64(100), rep.ServerBacklogP99)
		assert.Equal(t, int64(0), rep.PassMaxServerBacklog, "echo of the disabled ceiling")
		assert.Empty(t, rep.FailReasons)
	})

	t.Run("fails the run when max backlog exceeds the ceiling", func(t *testing.T) {
		t.Parallel()
		rep := &Report{Pass: true}
		aggregateServerBacklog(rep, []int64{100, 500, 37000, 200}, Options{PassMaxServerBacklog: 1000})
		assert.False(t, rep.Pass, "max 37000 over the 1000 ceiling fails the run")
		assert.Equal(t, int64(37000), rep.ServerBacklogMax)
		assert.Equal(t, int64(1000), rep.PassMaxServerBacklog)
		if assert.Len(t, rep.FailReasons, 1) {
			assert.Contains(t, rep.FailReasons[0], "server_backlog_max 37000 exceeds budget 1000")
		}
	})

	t.Run("passes when max backlog stays under the ceiling", func(t *testing.T) {
		t.Parallel()
		rep := &Report{Pass: true}
		aggregateServerBacklog(rep, []int64{120, 300, 415, 250}, Options{PassMaxServerBacklog: 1000})
		assert.True(t, rep.Pass, "a bounded backlog under the ceiling passes")
		assert.Equal(t, int64(415), rep.ServerBacklogMax)
		assert.Empty(t, rep.FailReasons)
	})

	t.Run("no samples is a no-op beyond echoing the ceiling", func(t *testing.T) {
		t.Parallel()
		rep := &Report{Pass: true}
		aggregateServerBacklog(rep, nil, Options{PassMaxServerBacklog: 1000})
		assert.True(t, rep.Pass)
		assert.Equal(t, 0, rep.ServerBacklogSamples)
		assert.Equal(t, int64(0), rep.ServerBacklogMax)
		assert.Equal(t, int64(1000), rep.PassMaxServerBacklog)
	})

	t.Run("does not resurrect an already-failed run", func(t *testing.T) {
		t.Parallel()
		rep := &Report{Pass: false, FailReasons: []string{"error_count > 0 (got 3)"}}
		aggregateServerBacklog(rep, []int64{120, 250}, Options{PassMaxServerBacklog: 1000})
		assert.False(t, rep.Pass, "a backlog under the ceiling must not flip a failed run back to pass")
		assert.Len(t, rep.FailReasons, 1, "no spurious backlog fail-reason added")
	})
}
