package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// fakeEventLog records the batchSize PruneProcessed was called with and returns a scripted (count, err). The other EventLog methods are
// unused by QueuePruneRunner, so they are inert.
type fakeEventLog struct {
	setAsidePruned []int
	pruneN         int64
	pruneErr       error
	gotBatch       int
	pruneCalled    int
}

func (f *fakeEventLog) Append(context.Context, []visibilityapi.Event) error { return nil }
func (f *fakeEventLog) PendingHosts(context.Context, int) ([]string, error) { return nil, nil }
func (f *fakeEventLog) ClaimForHost(context.Context, string, int) ([]visibilityapi.Event, error) {
	return nil, nil
}
func (f *fakeEventLog) Ack(context.Context, []string) error           { return nil }
func (f *fakeEventLog) Nack(context.Context, []string) (int64, error) { return 0, nil }
func (f *fakeEventLog) CountPending(context.Context) (int64, error)   { return 0, nil }
func (f *fakeEventLog) PruneProcessed(_ context.Context, batchSize int) (int64, error) {
	f.pruneCalled++
	f.gotBatch = batchSize
	return f.pruneN, f.pruneErr
}

// PruneSetAside records the retention window it was handed, so a test can assert the sweep passes the deployment's window through
// rather than a zero that would keep set-aside rows forever.
func (f *fakeEventLog) PruneSetAside(_ context.Context, retentionDays, _ int) (int64, error) {
	f.setAsidePruned = append(f.setAsidePruned, retentionDays)
	return 0, nil
}

func TestQueuePruneRunner_Run(t *testing.T) {
	t.Parallel()

	t.Run("prunes and reports the count", func(t *testing.T) {
		t.Parallel()
		log := &fakeEventLog{pruneN: 7}
		r := NewQueuePrune(log, QueuePruneOptions{BatchSize: 500}) // metrics nil: Run must stay nil-safe
		n, err := r.Run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, int64(7), n, "Run returns the pruned count")
		assert.Equal(t, 1, log.pruneCalled, "the sweep calls PruneProcessed once")
		assert.Equal(t, 500, log.gotBatch, "the configured batch size is passed through")
	})

	t.Run("propagates a prune error", func(t *testing.T) {
		t.Parallel()
		log := &fakeEventLog{pruneN: 3, pruneErr: errors.New("db down")}
		r := NewQueuePrune(log, QueuePruneOptions{})
		n, err := r.Run(context.Background())
		require.Error(t, err)
		assert.Equal(t, int64(3), n, "rows removed before the failure are still reported")
	})
}

// TestQueuePruneRunner_RecordsMetric pins that the configured recorder receives the pruned count.
func TestQueuePruneRunner_RecordsMetric(t *testing.T) {
	t.Parallel()
	log := &fakeEventLog{pruneN: 5}
	rec := &capturingRecorder{}
	r := NewQueuePrune(log, QueuePruneOptions{Metrics: rec})
	_, err := r.Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(5), rec.queuePruned, "the pruned count is recorded to the metrics recorder")
}

// capturingRecorder is a MetricsRecorder that captures the queue-prune count and the materialization-retry count; the rest are inert.
// setAsideCall is one EventsSetAside call, kept so a test can assert the host and count rather than only that it fired.
type setAsideCall struct {
	hostID string
	n      int64
}

type capturingRecorder struct {
	setAside               []setAsideCall
	queuePruned            int64
	materializationRetries int64
}

func (c *capturingRecorder) EventsIngested(context.Context, string, int) {}

// Not recorded: nothing in this package evaluates a rule, so a count here would only ever be zero.
func (c *capturingRecorder) RuleEvaluationSkipped(context.Context, string)                 {}
func (c *capturingRecorder) RuleEvaluationDuration(context.Context, string, time.Duration) {}
func (c *capturingRecorder) EventsSetAside(_ context.Context, hostID string, n int64) {
	c.setAside = append(c.setAside, setAsideCall{hostID: hostID, n: n})
}
func (c *capturingRecorder) EventsHeartbeatDropped(context.Context, string, int) {}
func (c *capturingRecorder) AlertCreated(context.Context, string, string)        {}
func (c *capturingRecorder) MonitorMatched(context.Context, string, string, int) {}
func (c *capturingRecorder) ProcessesTTLReconciled(context.Context, int64)       {}
func (c *capturingRecorder) ProcessRetentionRowsDeleted(context.Context, int64)  {}
func (c *capturingRecorder) QueueRowsPruned(_ context.Context, n int64)          { c.queuePruned += n }
func (c *capturingRecorder) DetectionMaterializationRetry(context.Context) {
	c.materializationRetries++
}
