package auditoutbox_test

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// memOutbox is an outbox in memory, counting the passes made over it: how many times the entries were read is what says whether two
// callers were answered by one pass or by a pass each.
type memOutbox struct {
	mu      sync.Mutex
	entries []auditoutbox.Pending
	nextID  int64
	reads   int
}

func (o *memOutbox) add(t *testing.T, action identityapi.AuditAction) {
	t.Helper()
	entry, err := auditoutbox.Encode(identityapi.AuditEvent{Action: action, TargetType: "host", TargetID: "host-a"})
	require.NoError(t, err)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nextID++
	o.entries = append(o.entries, auditoutbox.Pending{ID: o.nextID, Kind: entry.Kind, Payload: entry.Payload})
}

// addUnreadable adds an entry in an encoding this replica does not know, as a replica a version ahead writes during a rolling
// deploy. A pass skips it and never deletes it, so it stays at the head of the queue.
func (o *memOutbox) addUnreadable(kind string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nextID++
	o.entries = append(o.entries, auditoutbox.Pending{ID: o.nextID, Kind: kind, Payload: []byte(`{}`)})
}

func (o *memOutbox) PendingAuditEntries(_ context.Context, limit int) ([]auditoutbox.Pending, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads++
	if len(o.entries) > limit {
		return append([]auditoutbox.Pending(nil), o.entries[:limit]...), nil
	}
	return append([]auditoutbox.Pending(nil), o.entries...), nil
}

func (o *memOutbox) DeleteAuditEntries(_ context.Context, ids []int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	kept := o.entries[:0]
	for _, e := range o.entries {
		if !slices.Contains(ids, e.ID) {
			kept = append(kept, e)
		}
	}
	o.entries = kept
	return nil
}

func (o *memOutbox) passes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reads
}

func (o *memOutbox) pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

// heldRecorder is an audit store that is slow: every Record announces itself and then waits to be let go, which is how these tests
// hold a sweep mid-pass without sleeping for it.
type heldRecorder struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	got     []identityapi.AuditEvent
}

func newHeldRecorder() *heldRecorder {
	return &heldRecorder{started: make(chan struct{}, 8), release: make(chan struct{})}
}

func (r *heldRecorder) Record(ctx context.Context, e identityapi.AuditEvent) error {
	r.started <- struct{}{}
	select {
	case <-r.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, e)
	return nil
}

func (r *heldRecorder) recorded() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// spec:server-admin-surface/operator-actions-commit-their-audit-entry/a-slow-audit-store-does-not-delay-the-action
//
// DeliverSoon is what a change runs after committing, and the whole point of issue #1089 is that it does not wait for the audit
// store: the entry is already durable, the change already succeeded, and a slow store used to delay the response to a request whose
// destructive action had already been carried out. An operator who gives up on that response and retries has issued it twice.
//
// The recorder here is held inside Record, which is the state an audit-store outage leaves a sweep in, and DeliverSoon is required to
// return anyway.
func TestDeliverSoon_DoesNotWaitForTheAuditStore(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := newHeldRecorder()
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	go drain.SweepLoop(t.Context(), time.Hour)

	// A first change puts the sweep inside the recorder, where it stays until released.
	outbox.add(t, identityapi.AuditHostContain)
	drain.DeliverSoon(t.Context())
	<-recorder.started

	// A second change asks while the store is still holding the first. This is the request that used to wait.
	outbox.add(t, identityapi.AuditHostRelease)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		drain.DeliverSoon(t.Context())
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("DeliverSoon did not return while the audit store was busy, which is the wait issue #1089 removed")
	}

	close(recorder.release)
	require.Eventually(t, func() bool { return outbox.pending() == 0 && recorder.recorded() == 2 }, 10*time.Second, time.Millisecond,
		"both entries are delivered once the store answers")
}

// Callers that ask while a pass is running are answered by ONE further pass, not a pass each: a sweep reads the outbox when it runs,
// so what it delivers is everything committed by then. Without this a burst of changes would queue a read per change against a table
// that one read empties.
//
// Counting the reads is what makes this test able to fail. Asserting only that every row arrived would pass just as well with a pass
// per caller, which is the thing being ruled out.
func TestDeliverSoon_CallersArrivingTogetherAreAnsweredByOnePass(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := newHeldRecorder()
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	go drain.SweepLoop(t.Context(), time.Hour)

	outbox.add(t, identityapi.AuditHostContain)
	drain.DeliverSoon(t.Context())
	<-recorder.started // the first pass is now inside the recorder, so everything below arrives while it is busy

	const askers = 6
	for range askers {
		outbox.add(t, identityapi.AuditHostRelease)
		drain.DeliverSoon(t.Context())
	}
	close(recorder.release)

	require.Eventually(t, func() bool { return outbox.pending() == 0 }, 10*time.Second, time.Millisecond)
	assert.Equal(t, askers+1, recorder.recorded(), "every entry is delivered")
	// Two reads of the outbox: the pass that was running, and the one pass the six callers were coalesced into. A pass each would
	// be seven.
	assert.Equal(t, 2, outbox.passes(), "requests arriving during a pass are answered by one further pass, not one each")
}

// A burst larger than one pass is delivered in full without the interval. Every change in the burst asks for a pass, but the
// requests coalesce into one, and a pass takes at most DrainBatch: without a pass asking for the next one, entry DrainBatch+1 would
// sit in the outbox until the tick, which is a minute in production.
func TestDeliverSoon_ABurstLargerThanOnePassIsDeliveredWithoutTheInterval(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := &countingRecorder{}
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	// An interval far longer than the test, so nothing here can be delivered by a tick.
	go drain.SweepLoop(t.Context(), time.Hour)

	const burst = auditoutbox.DrainBatch + 1
	for range burst {
		outbox.add(t, identityapi.AuditHostContain)
	}
	drain.DeliverSoon(t.Context())

	require.Eventually(t, func() bool { return outbox.pending() == 0 }, 10*time.Second, time.Millisecond,
		"the entries past the first pass are delivered without waiting for the interval")
	assert.Equal(t, burst, recorder.count())
	// Two passes for DrainBatch+1 entries, and the second was asked for by the first.
	assert.Equal(t, 2, outbox.passes())
}

// A skipped entry does not stop the catch-up. A pass reads a full batch and delivers fewer than it read whenever one of them is in
// an encoding this replica does not know, which is what a rolling deploy produces. Continuing on the delivered count would leave
// everything behind that batch waiting for the interval because of one entry nobody could read.
func TestDeliverSoon_ABurstIsDrainedPastAnEntryThisReplicaCannotRead(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := &countingRecorder{}
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	go drain.SweepLoop(t.Context(), time.Hour)

	outbox.addUnreadable("identity.audit_event.v2")
	const readable = auditoutbox.DrainBatch
	for range readable {
		outbox.add(t, identityapi.AuditHostContain)
	}
	drain.DeliverSoon(t.Context())

	require.Eventually(t, func() bool { return recorder.count() == readable }, 10*time.Second, time.Millisecond,
		"the entries behind the unreadable one are delivered without waiting for the interval")
	// The unreadable entry is left for the replica that understands it, which is the only thing still in the outbox.
	assert.Equal(t, 1, outbox.pending())
}

// The catch-up stops when a pass delivers nothing, which is what keeps a replica that cannot read a full batch from re-reading it
// forever: a skipped entry is never deleted, so a pass asking for another pass on a batch it made no progress on would spin.
func TestSweepLoop_DoesNotSweepInALoopOverEntriesItCannotRead(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	drain, err := auditoutbox.NewDrain(outbox, &countingRecorder{}, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	go drain.SweepLoop(t.Context(), time.Hour)

	for range auditoutbox.DrainBatch {
		outbox.addUnreadable("identity.audit_event.v2")
	}
	drain.DeliverSoon(t.Context())

	// One pass for the one request, and no more: a second would mean the pass asked for itself again.
	assert.Never(t, func() bool { return outbox.passes() > 1 }, 300*time.Millisecond, 5*time.Millisecond)
	assert.Equal(t, 1, outbox.passes())
}

// spec:server-admin-surface/operator-actions-commit-their-audit-entry/an-entry-no-request-asked-about-is-still-delivered
//
// The interval is not made redundant by callers asking. A signal is in-process, so it is lost when the replica that raised it exits,
// and it never reaches the replica that has to deliver an entry another one wrote. Here nothing asks at all, as nothing on this
// replica did, and the entry is still delivered.
func TestSweepLoop_DeliversOnItsIntervalWhenNothingAsked(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := &countingRecorder{}
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	outbox.add(t, identityapi.AuditHostContain)
	go drain.SweepLoop(t.Context(), time.Millisecond)

	require.Eventually(t, func() bool { return recorder.count() == 1 && outbox.pending() == 0 }, 10*time.Second, time.Millisecond,
		"an entry no caller asked about is still delivered")
}

// A zero or negative interval means the default, which production wiring relies on: both bootstraps pass the configured interval
// through and it is zero unless set.
func TestSweepLoop_TreatsANonPositiveIntervalAsTheDefault(t *testing.T) {
	t.Parallel()
	outbox := &memOutbox{}
	recorder := &countingRecorder{}
	drain, err := auditoutbox.NewDrain(outbox, recorder, "test", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	outbox.add(t, identityapi.AuditHostContain)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		drain.SweepLoop(ctx, 0)
	}()

	// Nothing should have been delivered: the default is a minute, so a delivery inside this window would mean the zero was taken
	// literally and turned into a ticker that fires continuously.
	assert.Never(t, func() bool { return recorder.count() > 0 }, 100*time.Millisecond, 5*time.Millisecond)
	cancel()
	<-done
}

// A nil drain is the wiring with no audit recorder, which only non-production setups have. It says so rather than panicking on a
// change that has already committed.
func TestDeliverSoon_OnAnUnwiredDrainSaysSoRatherThanPanicking(t *testing.T) {
	t.Parallel()
	var drain *auditoutbox.Drain
	assert.NotPanics(t, func() { drain.DeliverSoon(t.Context()) })
}

// The interval pass reports what it delivered; a pass a change asked for does not. Entries reaching the interval mean rows are
// arriving later than the changes that wrote them, which is worth a line, while a line per operator action would say only that the
// server is working. The two are one switch apart, so the difference is pinned rather than left to the reader.
//
// The line says what the pass delivered and NOT that nothing asked for it: a request can arrive while the pass is running, and a
// request and the tick can be ready together, in which case either may be taken.
func TestSweepLoop_ReportsWhatTheIntervalPassDelivered(t *testing.T) {
	t.Parallel()
	t.Run("asked for", func(t *testing.T) {
		t.Parallel()
		logged, outbox, drain := loggingDrain(t)
		go drain.SweepLoop(t.Context(), time.Hour)
		outbox.add(t, identityapi.AuditHostContain)
		drain.DeliverSoon(t.Context())
		require.Eventually(t, func() bool { return outbox.pending() == 0 }, 10*time.Second, time.Millisecond)
		assert.NotContains(t, logged.String(), "periodic sweep", "a delivery a change asked for is not news")
	})

	t.Run("delivered on the interval", func(t *testing.T) {
		t.Parallel()
		logged, outbox, drain := loggingDrain(t)
		outbox.add(t, identityapi.AuditHostContain)
		go drain.SweepLoop(t.Context(), time.Millisecond)
		require.Eventually(t, func() bool { return outbox.pending() == 0 }, 10*time.Second, time.Millisecond)
		assert.Eventually(t, func() bool { return bytes.Contains(logged.Bytes(), []byte("periodic sweep")) }, 10*time.Second,
			time.Millisecond, "a row arriving later than the change that wrote it is what the outbox exists to report")
	})
}

// loggingDrain is a drain whose log lines a test can read.
func loggingDrain(t *testing.T) (*syncBuffer, *memOutbox, *auditoutbox.Drain) {
	t.Helper()
	logged := &syncBuffer{}
	outbox := &memOutbox{}
	drain, err := auditoutbox.NewDrain(outbox, &countingRecorder{}, "test", slog.New(slog.NewTextHandler(logged, nil)))
	require.NoError(t, err)
	return logged, outbox, drain
}

// syncBuffer is a log sink written by the sweep's goroutine and read by the test's.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *syncBuffer) String() string { return string(b.Bytes()) }

// countingRecorder accepts everything and counts it.
type countingRecorder struct {
	mu sync.Mutex
	n  int
}

func (r *countingRecorder) Record(context.Context, identityapi.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	return nil
}

func (r *countingRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}
