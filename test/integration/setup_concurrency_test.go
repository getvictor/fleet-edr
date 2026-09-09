//go:build integration

// Per-PR coverage for the harness's own multi-worker path.
//
// The pool sizing and coordinator wiring that Setup does for a multi-worker stack is what issue #962 turned out to be: the scale
// gate asked for the production fan-out, the harness silently gave it one worker, and the shortfall read as a throughput
// regression in the product for three weeks. The gate that would now catch a repeat is behind the `scalegate` build tag, which
// the per-PR job does not run, so without this file a regression in the same wiring could merge and stay hidden until the
// weekly or RC lane. These cases run on every PR and take no measurable time: they wire a stack and ask it what it will run.

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/config"
)

func TestSetup_ProvisionsTheRequestedProcessorFanOut(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// opts is nil for the historical single-worker default, so the default path is pinned alongside the multi-worker one.
		opts []Option
		want int
	}{
		{
			name: "the default stack runs the historical single worker",
			opts: nil,
			want: 1,
		},
		{
			name: "the production fan-out is provisioned for, not just requested",
			opts: []Option{WithProcessConcurrency(config.DefaultProcessConcurrency)},
			want: config.DefaultProcessConcurrency,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stack := Setup(t, tc.opts...)
			// The EFFECTIVE count, which is the only one worth asserting: the processor reduces its fleet to what the harness can
			// actually support and says so in a WARN nobody reads, so a request that was not honored looks identical to one that
			// was until something downstream measures throughput and blames the product.
			require.Equal(t, tc.want, stack.Detection.ProcessorConcurrency(),
				"Setup must provision the pool and coordinator the requested fan-out needs, not merely pass the number down")
		})
	}
}
