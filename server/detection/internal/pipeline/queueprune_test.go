package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// fakeEventLog records the batchSize PruneProcessed was called with and returns a scripted (count, err). The other EventLog methods are
// unused by QueuePruneRunner, so they are inert.
type fakeEventLog struct {
	pruneN      int64
	pruneErr    error
	gotBatch    int
	pruneCalled int
}

func (f *fakeEventLog) Append(context.Context, []visibilityapi.Event) error       { return nil }
func (f *fakeEventLog) Claim(context.Context, int) ([]visibilityapi.Event, error) { return nil, nil }
func (f *fakeEventLog) Ack(context.Context, []string) error                       { return nil }
func (f *fakeEventLog) Nack(context.Context, []string) error                      { return nil }
func (f *fakeEventLog) CountPending(context.Context) (int64, error)               { return 0, nil }
func (f *fakeEventLog) PruneProcessed(_ context.Context, batchSize int) (int64, error) {
	f.pruneCalled++
	f.gotBatch = batchSize
	return f.pruneN, f.pruneErr
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

// capturingRecorder is a MetricsRecorder that only captures the queue-prune count; the rest are inert.
type capturingRecorder struct{ queuePruned int64 }

func (c *capturingRecorder) EventsIngested(context.Context, string, int)         {}
func (c *capturingRecorder) EventsHeartbeatDropped(context.Context, string, int) {}
func (c *capturingRecorder) AlertCreated(context.Context, string, string)        {}
func (c *capturingRecorder) ProcessesTTLReconciled(context.Context, int64)       {}
func (c *capturingRecorder) RetentionRowsDeleted(context.Context, int64)         {}
func (c *capturingRecorder) ProcessRetentionRowsDeleted(context.Context, int64)  {}
func (c *capturingRecorder) QueueRowsPruned(_ context.Context, n int64)          { c.queuePruned += n }
