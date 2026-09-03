package bootstrap_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/bootstrap"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

// retentionRecordingEventLog forwards everything to a real EventLog and records only what PruneSetAside was asked to keep.
//
// Embedded rather than hand-written so the fake cannot drift from the interface: a new EventLog method compiles here unchanged, and
// the surrounding pipeline exercises the real store for everything except the one observation.
type retentionRecordingEventLog struct {
	visibilityapi.EventLog
	mu        sync.Mutex
	retention []int
}

func (l *retentionRecordingEventLog) PruneSetAside(ctx context.Context, retentionDays, batchSize int) (int64, error) {
	l.mu.Lock()
	l.retention = append(l.retention, retentionDays)
	l.mu.Unlock()
	return l.EventLog.PruneSetAside(ctx, retentionDays, batchSize)
}

func (l *retentionRecordingEventLog) seen() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]int(nil), l.retention...)
}

// TestQueuePruneWiring_RetentionReachesTheSetAsideSweep covers the ONE hop a struct-literal omission silently breaks.
//
// RetentionDays was genuinely missing from this bootstrap's QueuePruneOptions literal when the set-aside sweep was written, which
// would have shipped the whole feature dead: entries withdrawn from the queue would accumulate for the life of the deployment and
// the operator's inspection window would never close because it never opened. Nothing failed. The runner-level test builds its
// runner directly, so it proves the runner passes the window it was given and says nothing about what this file gives it, and the
// acked-row half of the same sweep ignores retention entirely, so the runner keeps logging pruned rows either way.
//
// Driven through the real Run loop rather than by reaching for an internal, because the loop is what a deployment executes: the
// sweep fires once immediately, which is all this needs, and the wiring is only real if the goroutine that bootstrap starts is the
// one that carries the value.
func TestQueuePruneWiring_RetentionReachesTheSetAsideSweep(t *testing.T) {
	t.Parallel()
	db := full.Open(t)

	vis, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db})
	require.NoError(t, err)
	recorder := &retentionRecordingEventLog{EventLog: vis.EventLog()}

	const retentionDays = 21
	d, err := bootstrap.New(bootstrap.Deps{
		DB:            db,
		Mode:          bootstrap.ModeFull,
		AuthZ:         identitytestkit.AllowAllAuthZ{},
		EventLog:      recorder,
		EventArchive:  detectiontestkit.NewMemArchive(),
		RetentionDays: retentionDays,
		// Every interval is set long on purpose. The sweep this asserts on is the immediate one, so a second tick would only make
		// the assertion depend on timing, and the other loops have nothing to do here. ProcessInterval must be set at all: unlike
		// QueuePruneInterval it has no zero-default, so a zero panics the processor's ticker once Run starts.
		ProcessInterval:      time.Hour,
		StaleProcessInterval: time.Hour,
		RetentionInterval:    time.Hour,
		QueuePruneInterval:   time.Hour,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()

	require.Eventually(t, func() bool { return len(recorder.seen()) > 0 }, 10*time.Second, 20*time.Millisecond,
		"bootstrap must hand the queue-prune sweep the deployment's retention window")
	cancel()
	<-done

	assert.Equal(t, retentionDays, recorder.seen()[0],
		"a zero here keeps set-aside rows for the life of the deployment, and the acked-row half of the sweep hides it")
}
