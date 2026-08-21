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

// waitForCall blocks until one enable has landed AND the controller has finished accounting for it, failing the test rather than
// hanging forever if it does not.
//
// Both halves are needed, and waiting only for the first was issue #740. The fake signals from INSIDE Enable, before it returns,
// while the controller does its bookkeeping in remediate() AFTER that call returns: under one lock hold it clears `remediating`
// and sets the next `eligibleAt`. A test that advances the clock and observes in that window hits one of two gates in plan(),
// `st.remediating || now.Before(st.eligibleAt)`, and launches nothing:
//
//   - `remediating` is still true, because the goroutine has not reached its bookkeeping yet; or
//   - `eligibleAt` is computed from the ALREADY-ADVANCED clock, so the next attempt is not yet due.
//
// Both present identically, as "attempt N should launch" against a nil return, which is why the failure moved between subtests and
// attempt numbers. It reproduced at 10 in 300 under -race and never in 300 without: the race detector's scheduling is what widens
// the window, so it failed on CI and effectively never locally.
//
// Waiting on `remediating` alone is sufficient for both: the two writes happen under the same lock hold, so observing it cleared
// while holding c.mu means eligibleAt is set as well. Taking the controller rather than only the fake is the point of the
// signature: the state a caller must wait for belongs to the controller, and there is no correct way to wait for it from the
// remediator alone.
func (f *fakeRemediator) waitForCall(t *testing.T, c *Controller) string {
	t.Helper()
	var provider string
	select {
	case provider = <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a remediation")
		return ""
	}
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		st := c.state[provider]
		// A cleared entry is settled too: the provider was reported running while the attempt was in flight, so remediate
		// returned without resurrecting it.
		return st == nil || !st.remediating
	}, 2*time.Second, 50*time.Microsecond,
		"the controller never finished recording the %s attempt, so the next observation would race its bookkeeping", provider)
	return provider
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
	assert.Equal(t, "content_filter", rem.waitForCall(t, c))
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
		rem.waitForCall(t, c)
	}
	require.Eventually(t, func() bool { return hs.count() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"exhausting the budget must escalate so the operator sees automation gave up")
	assert.Contains(t, hs.failures[0], "content_filter")
	assert.Contains(t, hs.failures[0], "operator action required")

	// Budget spent: further reports must not launch anything, however long the provider stays stopped, AND each report must
	// re-assert the escalation. The receiver loop calls MarkProviders before Observe, so every report overwrites the reason
	// with provider_stopped; without the re-assertion self_heal_failed would survive microseconds and the operator would
	// never see that automation had given up.
	for range 3 {
		clock.advance(10 * time.Minute)
		before := hs.count()
		assert.Empty(t, c.Observe(ctx, stoppedFilter))
		assert.Equal(t, before+1, hs.count(), "every report while exhausted must re-assert the escalation")
	}
	assert.Equal(t, 3, rem.callCount(), "must not exceed the attempt budget")
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
		rem.waitForCall(t, c)
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
	rem.waitForCall(t, c)
	assert.Equal(t, 4, rem.callCount())
}

// spec:agent-status-reporting/remediation-attempts-are-bounded-and-escalate-on-exhaustion/repeated-failures-stop-retrying-and-escalate
func TestEnablesThatSucceedButNeverRestoreTheProviderAreAlsoBounded(t *testing.T) {
	t.Parallel()
	// The nastier half of the bound. Every enable is ACCEPTED, so the error path never runs, but the provider stays
	// stopped in every report. A budget that only counted failures would retry forever here, rewriting NetworkExtension
	// preferences indefinitely while the host stayed blind, which is exactly the repair loop the design forbids.
	rem := newFakeRemediator(nil)
	hs := &fakeHealth{}
	c, clock := testController(t, rem, hs)
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	for attempt := 1; attempt <= 3; attempt++ {
		clock.advance(2 * time.Minute)
		require.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter), "attempt %d should launch", attempt)
		rem.waitForCall(t, c)
	}
	require.Eventually(t, func() bool { return hs.count() >= 1 }, 2*time.Second, 10*time.Millisecond)
	// The diagnosis must distinguish this from "the enable kept failing": here the command worked every time and the
	// provider still is not capturing, so re-enabling is not what the fault needs.
	assert.Contains(t, hs.failures[0], "still not capturing")

	for range 3 {
		clock.advance(10 * time.Minute)
		assert.Empty(t, c.Observe(ctx, stoppedFilter))
	}
	assert.Equal(t, 3, rem.callCount(), "a succeeding-but-ineffective enable must still burn the budget")
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

// spec:agent-status-reporting/remediation-attempts-are-bounded-and-escalate-on-exhaustion/repeated-failures-stop-retrying-and-escalate
func TestFlappingBetweenStoppedAndAbsentDoesNotRefreshTheBudget(t *testing.T) {
	t.Parallel()
	// Absence is NOT recovery. A provider is also absent when the operator disabled it, when nothing has started yet, and
	// when parseProviderStatus could not decode the payload and returned an empty map. If absence reset the budget, a
	// provider alternating between stopped and absent would get a fresh three attempts every cycle and maxAttempts would
	// bound nothing, so the agent would rewrite NetworkExtension preferences forever while the host stayed blind.
	rem := newFakeRemediator(errors.New("save failed"))
	c, clock := testController(t, rem, &fakeHealth{})
	ctx := context.Background()
	absent := map[string]string{}

	for range 10 {
		clock.advance(2 * time.Minute)
		if launched := c.Observe(ctx, stoppedFilter); len(launched) > 0 {
			rem.waitForCall(t, c)
		}
		clock.advance(2 * time.Minute)
		c.Observe(ctx, absent) // ambiguous: must be treated as "no new information"
	}
	assert.LessOrEqual(t, rem.callCount(), 3, "absence must not hand back a fresh attempt budget")
}

func TestAffirmativeRunningReportRestoresTheBudget(t *testing.T) {
	t.Parallel()
	// The counterpart to the flap test: an explicit running report IS proof the heal took, so it clears the state.
	rem := newFakeRemediator(errors.New("save failed"))
	c, clock := testController(t, rem, &fakeHealth{})
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	for range 3 {
		clock.advance(2 * time.Minute)
		require.NotEmpty(t, c.Observe(ctx, stoppedFilter))
		rem.waitForCall(t, c)
	}
	clock.advance(10 * time.Minute)
	require.Empty(t, c.Observe(ctx, stoppedFilter), "budget spent")

	c.Observe(ctx, map[string]string{"content_filter": ProviderRunning})
	c.Observe(ctx, stoppedFilter)
	clock.advance(2 * time.Minute)
	assert.NotEmpty(t, c.Observe(ctx, stoppedFilter), "a running report must restore the budget")
}

func TestAttemptsAreSpacedByBackoffAloneNotBackoffPlusGrace(t *testing.T) {
	t.Parallel()
	// The grace window is a property of the STOP, not of each retry. Re-applying it per attempt made the real gap
	// backoff + grace, which is neither what the constants say nor what a reader would predict.
	rem := newFakeRemediator(errors.New("save failed"))
	c, clock := testController(t, rem, &fakeHealth{}) // grace 30s, backoff 1s
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	clock.advance(31 * time.Second) // past the grace window
	require.NotEmpty(t, c.Observe(ctx, stoppedFilter), "first attempt after grace")
	rem.waitForCall(t, c)

	// Attempt 2 is eligible one backoff later (1s * attempt 1), NOT one backoff plus another full grace window.
	clock.advance(2 * time.Second)
	assert.NotEmpty(t, c.Observe(ctx, stoppedFilter), "second attempt must be eligible after the backoff alone")
}

// escalationRecorder captures the edge-triggered escalation callback. Mutex-guarded because the controller invokes it from
// the remediation goroutine, not from Observe.
type escalationRecorder struct {
	mu   sync.Mutex
	seen []Escalation
}

func (r *escalationRecorder) record(e Escalation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, e)
}

func (r *escalationRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

func (r *escalationRecorder) first() Escalation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[0]
}

// testControllerWithEscalation is testController plus the escalation callback under test.
func testControllerWithEscalation(t *testing.T, rem Remediator, hs HealthSink, rec *escalationRecorder) (*Controller, *testClock) {
	t.Helper()
	clock := &testClock{t: time.Unix(1_700_000_000, 0)}
	c := New(Options{
		Remediator:   rem,
		Health:       hs,
		Component:    "network_extension",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Grace:        30 * time.Second,
		MaxAttempts:  3,
		Backoff:      time.Second,
		Now:          clock.now,
		OnEscalation: rec.record,
	})
	return c, clock
}

// exhaustBudget drives one provider through every attempt in the budget, leaving the controller escalated.
func exhaustBudget(t *testing.T, c *Controller, clock *testClock, rem *fakeRemediator) {
	t.Helper()
	ctx := context.Background()
	c.Observe(ctx, stoppedFilter)
	for attempt := 1; attempt <= 3; attempt++ {
		clock.advance(2 * time.Minute)
		require.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter), "attempt %d should launch", attempt)
		rem.waitForCall(t, c)
	}
}

// spec:agent-status-reporting/an-exhausted-repair-is-recorded-durably-once/the-record-is-not-repeated-while-the-provider-stays-stopped
//
// TestEscalationIsReportedOnceEvenWhileHealthIsReasserted is the whole reason the escalation seam is edge-triggered rather
// than hanging off escalate() (issue #691).
//
// Health is level state that something else keeps overwriting, so the controller re-asserts it on EVERY report for as long
// as the provider stays down; the sibling test above pins exactly that. A durable event is an append, so the same
// treatment would produce one event, and therefore one alert, per liveness report. The extension re-publishes liveness on
// every agent handshake, so "per report" is a storm, not a duplicate.
//
// The assertion is deliberately a CONTRAST: over the same reports, health fires repeatedly and the escalation fires once.
// Asserting the escalation count alone would still pass if someone moved the call into escalate() and the test happened
// not to drive enough reports.
func TestEscalationIsReportedOnceEvenWhileHealthIsReasserted(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(errors.New("save failed"))
	hs := &fakeHealth{}
	rec := &escalationRecorder{}
	c, clock := testControllerWithEscalation(t, rem, hs, rec)
	ctx := context.Background()

	exhaustBudget(t, c, clock, rem)
	require.Eventually(t, func() bool { return rec.count() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"exhausting the budget must report the escalation once")

	healthBefore := hs.count()
	for range 5 {
		clock.advance(10 * time.Minute)
		assert.Empty(t, c.Observe(ctx, stoppedFilter))
	}
	assert.Greater(t, hs.count(), healthBefore, "health must keep being re-asserted, as the level-state contract requires")
	assert.Equal(t, 1, rec.count(), "the durable escalation must fire once per stop episode, not once per report")
}

// spec:agent-status-reporting/an-exhausted-repair-is-recorded-durably-once/an-exhausted-repair-is-recorded
//
// TestEscalationNamesWhichFailureShapeItWas pins the field an analyst acts on. The two shapes implicate different parts of
// the host (the repair command failing points at the host app; the repair succeeding without effect means re-enabling is
// not what the fault needs), so collapsing them into "it failed" would discard the useful half.
func TestEscalationNamesWhichFailureShapeItWas(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		enableErr   error
		wantOutcome string
	}{
		{"every enable failed", errors.New("save failed"), OutcomeEnableFailed},
		{"every enable succeeded and it stayed stopped", nil, OutcomeEnableIneffective},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rem := newFakeRemediator(tc.enableErr)
			rec := &escalationRecorder{}
			c, clock := testControllerWithEscalation(t, rem, &fakeHealth{}, rec)

			exhaustBudget(t, c, clock, rem)
			require.Eventually(t, func() bool { return rec.count() >= 1 }, 2*time.Second, 10*time.Millisecond)

			got := rec.first()
			assert.Equal(t, "content_filter", got.Provider)
			assert.Equal(t, tc.wantOutcome, got.Outcome)
			assert.Equal(t, 3, got.Attempts, "the attempt count is carried so the finding can say the repair was really tried")
		})
	}
}

// spec:agent-status-reporting/an-exhausted-repair-is-recorded-durably-once/a-successful-repair-records-nothing
//
// TestNoEscalationWhenTheProviderComesBack covers the ordinary case, which must stay silent. A repair that works is not an
// operator-facing event, and reporting one would put an alert on every self-healed host.
func TestNoEscalationWhenTheProviderComesBack(t *testing.T) {
	t.Parallel()
	rem := newFakeRemediator(nil)
	rec := &escalationRecorder{}
	c, clock := testControllerWithEscalation(t, rem, &fakeHealth{}, rec)
	ctx := context.Background()

	c.Observe(ctx, stoppedFilter)
	clock.advance(2 * time.Minute)
	require.Equal(t, []string{"content_filter"}, c.Observe(ctx, stoppedFilter))
	rem.waitForCall(t, c)

	// The extension's next report shows it running, which is the only authority on recovery.
	clock.advance(2 * time.Minute)
	assert.Empty(t, c.Observe(ctx, map[string]string{"content_filter": "running"}))
	clock.advance(10 * time.Minute)
	assert.Empty(t, c.Observe(ctx, map[string]string{"content_filter": "running"}))

	assert.Zero(t, rec.count(), "a provider that came back must produce no escalation")
}
