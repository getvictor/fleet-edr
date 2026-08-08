package selfheal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRemediator records enable calls and signals each one so tests can wait for the controller's goroutine rather than
// sleeping. err is what Enable returns; swap it to drive the failure paths.
type fakeRemediator struct {
	mu    sync.Mutex
	calls []string
	err   error
	done  chan string
}

func newFakeRemediator(err error) *fakeRemediator {
	return &fakeRemediator{err: err, done: make(chan string, 16)}
}

func (f *fakeRemediator) Enable(_ context.Context, provider string) error {
	f.mu.Lock()
	f.calls = append(f.calls, provider)
	err := f.err
	f.mu.Unlock()
	f.done <- provider
	return err
}

func (f *fakeRemediator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// waitForCall blocks until one enable lands, failing the test rather than hanging forever if it does not.
func (f *fakeRemediator) waitForCall(t *testing.T) string {
	t.Helper()
	select {
	case p := <-f.done:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a remediation")
		return ""
	}
}

// fakeHealth captures the escalation the controller publishes when it gives up.
type fakeHealth struct {
	mu       sync.Mutex
	failures []string
}

func (h *fakeHealth) MarkSelfHealFailed(_, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures = append(h.failures, message)
}

func (h *fakeHealth) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.failures)
}

// testClock is a manually advanced clock. Mutex-guarded because the controller reads it from its remediation goroutine
// while the test advances it, which -race correctly flags on a bare time.Time.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testController builds a controller on a manually advanced clock so the grace window and backoff are driven by the test
// rather than by wall-clock sleeps.
func testController(t *testing.T, rem Remediator, hs HealthSink) (*Controller, *testClock) {
	t.Helper()
	clock := &testClock{t: time.Unix(1_700_000_000, 0)}
	c := New(Options{
		Remediator:  rem,
		Health:      hs,
		Component:   "network_extension",
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Grace:       30 * time.Second,
		MaxAttempts: 3,
		Backoff:     time.Second,
		Now:         clock.now,
	})
	return c, clock
}

var stoppedFilter = map[string]string{"content_filter": "stopped"}

// spec:agent-status-reporting/the-agent-restores-stopped-capture-providers/a-stopped-provider-is-re-enabled
func TestStoppedProviderIsRemediatedAfterTheGraceWindow(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(nil)
	c, clock := testController(t, rem, nil)
	ctx := context.Background()

	// First report only opens the grace window; a stop is routine mid-activation and usually clears on its own.
	assert.Empty(t, c.Observe(ctx, stoppedFilter), "must not remediate on the first report")
	clock.advance(29 * time.Second)
	assert.Empty(t, c.Observe(ctx, stoppedFilter), "must not remediate before the grace window expires")

	clock.advance(2 * time.Second)
	assert.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter))
	assert.Equal(t, "content_filter", rem.waitForCall(t))
}

// spec:agent-status-reporting/the-agent-restores-stopped-capture-providers/a-provider-that-recovers-on-its-own-is-left-alone
func TestProviderThatRecoversWithinGraceIsNotRemediated(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(nil)
	c, clock := testController(t, rem, nil)
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	clock.advance(10 * time.Second)
	// The provider came back on its own, which is the common case during an activation or upgrade cutover.
	c.Observe(ctx, map[string]string{"content_filter": "running"})
	clock.advance(60 * time.Second)
	// Even well past the original grace window, the recovered provider must not be touched: the state was cleared.
	assert.Empty(t, c.Observe(ctx, map[string]string{"content_filter": "running"}))
	assert.Zero(t, rem.callCount())
}

// spec:agent-status-reporting/remediation-never-overrides-a-deliberate-operator-decision/a-deliberately-disabled-provider-is-not-re-enabled
func TestDeliberatelyDisabledProviderIsNeverRemediated(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(nil)
	c, clock := testController(t, rem, nil)
	ctx := context.Background()

	// An operator disabled the opt-in DNS proxy, so #649 reports it ABSENT rather than stopped. No amount of elapsed time
	// may turn that into a remediation, or the product would keep switching a control back on against its administrator.
	report := map[string]string{"content_filter": "running"}
	for range 5 {
		assert.Empty(t, c.Observe(ctx, report))
		clock.advance(time.Minute)
	}
	assert.Zero(t, rem.callCount())
}

// spec:agent-status-reporting/remediation-attempts-are-bounded-and-escalate-on-exhaustion/repeated-failures-stop-retrying-and-escalate
func TestRepeatedFailuresStopRetryingAndEscalate(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(errors.New("save failed"))
	hs := &fakeHealth{}
	c, clock := testController(t, rem, hs)
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	// Three attempts, each separated by the backoff the previous failure pushed out.
	for attempt := 1; attempt <= 3; attempt++ {
		clock.advance(2 * time.Minute)
		require.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter), "attempt %d should launch", attempt)
		rem.waitForCall(t)
	}
	// Budget spent: further reports must not launch anything, however long the provider stays stopped.
	for range 3 {
		clock.advance(10 * time.Minute)
		assert.Empty(t, c.Observe(ctx, stoppedFilter))
	}
	assert.Equal(t, 3, rem.callCount(), "must not exceed the attempt budget")

	require.Eventually(t, func() bool { return hs.count() == 1 }, 2*time.Second, 10*time.Millisecond,
		"exhaustion must escalate exactly once so the operator sees automation gave up")
	assert.Contains(t, hs.failures[0], "content_filter")
	assert.Contains(t, hs.failures[0], "operator action required")
}

// spec:agent-status-reporting/remediation-attempts-are-bounded-and-escalate-on-exhaustion/a-successful-remediation-restores-the-budget
func TestSuccessfulRemediationRestoresTheBudget(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(errors.New("save failed"))
	hs := &fakeHealth{}
	c, clock := testController(t, rem, hs)
	ctx := context.Background()

	// Burn the whole budget on a stop that never recovers.
	c.Observe(ctx, stoppedFilter)
	for range 3 {
		clock.advance(2 * time.Minute)
		require.NotEmpty(t, c.Observe(ctx, stoppedFilter))
		rem.waitForCall(t)
	}
	require.Eventually(t, func() bool { return hs.count() == 1 }, 2*time.Second, 10*time.Millisecond)
	clock.advance(10 * time.Minute)
	require.Empty(t, c.Observe(ctx, stoppedFilter), "budget is spent")

	// The provider comes back by some other route (a reboot, a manual activate, an operator toggle).
	c.Observe(ctx, map[string]string{"content_filter": "running"})

	// A later stop must get a full budget again: a host that fails intermittently over weeks should be retried each time,
	// not written off permanently by one bad afternoon.
	clock.advance(time.Minute)
	c.Observe(ctx, stoppedFilter)
	clock.advance(2 * time.Minute)
	assert.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter))
	rem.waitForCall(t)
	assert.Equal(t, 4, rem.callCount())
}

func TestOnlyOneRemediationRunsPerProviderAtATime(t *testing.T) {
	t.Parallel()
	// Reports keep arriving during the seconds an enable takes; a second launch would write the same configuration twice
	// and double-count the attempt budget.
	release := make(chan struct{})
	rem := &blockingRemediator{release: release, entered: make(chan struct{}, 4)}
	c, clock := testController(t, rem, nil)
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	clock.advance(time.Minute)
	require.NotEmpty(t, c.Observe(ctx, stoppedFilter))
	<-rem.entered

	for range 3 {
		clock.advance(time.Minute)
		assert.Empty(t, c.Observe(ctx, stoppedFilter), "must not launch while one is in flight")
	}
	close(release)
	assert.Equal(t, 1, rem.count())
}

func TestNilRemediatorMakesTheControllerANoOp(t *testing.T) {
	t.Parallel()
	// Non-darwin builds get a nil remediator: there are no NetworkExtension providers to restore, so Observe must be inert
	// rather than panicking on the missing dependency.
	c := New(Options{Component: "network_extension", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	assert.Empty(t, c.Observe(context.Background(), stoppedFilter))
}

func TestDefaultsAreAppliedForZeroValuedOptions(t *testing.T) {
	t.Parallel()
	c := New(Options{Remediator: newFakeRemediator(nil)})
	assert.Equal(t, defaultGrace, c.grace)
	assert.Equal(t, defaultMaxAttempts, c.maxAttempts)
	assert.Equal(t, defaultBackoff, c.backoff)
	assert.NotNil(t, c.now)
	assert.NotNil(t, c.logger)
}

// blockingRemediator holds Enable open until released, so a test can observe the in-flight window.
type blockingRemediator struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
	entered chan struct{}
}

func (b *blockingRemediator) Enable(context.Context, string) error {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.entered <- struct{}{}
	<-b.release
	return nil
}

func (b *blockingRemediator) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}
