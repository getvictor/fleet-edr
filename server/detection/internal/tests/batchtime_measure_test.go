//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
)

// TestMeasureBatchProcessingTime establishes the figure issue #837 notes was never established: how long the pipeline takes to
// process one batch end to end.
//
// Without it the per-batch statistics write could only be compared against rule-evaluation time, which is the smaller of the two
// and makes the write look worse than a reader can verify. With it the write's cost can be stated as a fraction of the work the
// batch actually does.
//
// Measured as a full drain rather than by timing an internal call, because the Processor is deliberately not exposed on the
// bootstrap and exporting it to measure it would be a worse trade than measuring the thing an operator cares about anyway: how
// long a batch takes from ingest to acknowledged.
//
// Skipped unless EDR_MEASURE is set; it is a measurement with no pass condition beyond completing.
//
//	EDR_MEASURE=1 EDR_TEST_DSN='root@tcp(127.0.0.1:33307)/edr_test?parseTime=true' \
//	  go test -tags integration -run TestMeasureBatchProcessingTime -v ./server/detection/internal/tests/
func TestMeasureBatchProcessingTime(t *testing.T) {
	if os.Getenv("EDR_MEASURE") == "" {
		t.Skip("set EDR_MEASURE=1 to run the batch-processing-time measurement")
	}

	const batches, eventsPerBatch = 12, 100

	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(runCtx) }()

	pending := func() int64 {
		n, err := d.Service().CountUnprocessed(ctx)
		require.NoError(t, err)
		return n
	}

	samples := make([]time.Duration, 0, batches)
	for b := range batches {
		events := make([]api.Event, 0, eventsPerBatch)
		host := fmt.Sprintf("measure-host-%02d", b)
		for i := range eventsPerBatch {
			ts := int64(1000 + i*10)
			events = append(events, api.Event{
				EventID: fmt.Sprintf("%s-e%03d", host, i), HostID: host, TimestampNs: ts, EventType: "exec",
				Payload: json.RawMessage(fmt.Sprintf(
					`{"pid":%d,"ppid":1,"path":"/bin/zsh","args":["zsh","-c","true"],"uid":501,"gid":20}`, 100+i)),
			})
		}

		// Wait for a quiet queue first, so the sample times THIS batch rather than a backlog.
		require.Eventually(t, func() bool { return pending() == 0 }, 60*time.Second, 5*time.Millisecond)

		start := time.Now()
		insertEventsViaIngest(ctx, t, d, host, events)
		require.Eventually(t, func() bool { return pending() == 0 }, 60*time.Second, 2*time.Millisecond,
			"batch %d did not drain", b)
		samples = append(samples, time.Since(start))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pct := func(p float64) time.Duration { return samples[int(float64(len(samples)-1)*p)] }
	t.Logf("batch drain (ingest to acknowledged), %d events per batch, %d batches: p50=%v p95=%v max=%v",
		eventsPerBatch, batches,
		pct(0.50).Round(time.Millisecond), pct(0.95).Round(time.Millisecond), samples[len(samples)-1].Round(time.Millisecond))
}
