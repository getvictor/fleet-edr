package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

const overBudget = maxRuleEvalNs + 1

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-rule-over-budget-on-one-batch-is-still-evaluated-on-the-next
// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-rule-repeatedly-over-budget-stops-being-evaluated
//
// TestEvalBudget_SkipsOnlyAfterBothBoundsAreExceeded covers the twin bounds, which exist because one overrun is not evidence.
//
// The measured reason: across 219 evaluations of the vendored corpus the mean was 0.094ms and one rule doing legitimate work took
// 17.8ms, on both of its two evaluations. A single-overrun rule would have skipped it on a sample that small.
func TestEvalBudget_SkipsOnlyAfterBothBoundsAreExceeded(t *testing.T) {
	t.Parallel()
	now := time.Now()

	t.Run("one overrun does not skip", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		exhausted, _ := b.record("slow", overBudget, now)
		assert.False(t, exhausted)
		assert.False(t, b.skipping("slow"), "a cold cache or an oversized batch produces exactly this")
	})

	t.Run("one short of the count does not skip", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		for range maxRuleOverruns - 1 {
			b.record("slow", overBudget, now)
		}
		assert.False(t, b.skipping("slow"))
	})

	t.Run("reaching the count skips, and reports the transition once", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		transitions := 0
		for range maxRuleOverruns {
			if exhausted, _ := b.record("slow", overBudget, now); exhausted {
				transitions++
			}
		}
		require.True(t, b.skipping("slow"))
		assert.Equal(t, 1, transitions, "the caller logs and counts on the transition, so it must be reported exactly once")

		// Further overruns must not re-report: a rule that costs nothing because it is skipped would otherwise look like the
		// busiest thing in the fleet.
		for range maxRuleOverruns {
			exhausted, _ := b.record("slow", overBudget, now)
			assert.False(t, exhausted)
		}
	})

	t.Run("overruns spread beyond the window never accumulate", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		at := now
		for range maxRuleOverruns * 3 {
			b.record("occasionally-slow", overBudget, at)
			at = at.Add(ruleOverrunWindow + time.Second)
		}
		assert.False(t, b.skipping("occasionally-slow"),
			"the window is what makes the count mean 'repeatedly, lately' instead of 'eventually'")
	})

	t.Run("an evaluation inside the budget clears the run", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		for range maxRuleOverruns - 1 {
			b.record("mostly-fine", overBudget, now)
		}
		b.record("mostly-fine", maxRuleEvalNs, now)
		for range maxRuleOverruns - 1 {
			b.record("mostly-fine", overBudget, now)
		}
		assert.False(t, b.skipping("mostly-fine"),
			"a rule that is occasionally slow and usually fine must never reach the bound")
	})

	t.Run("exactly at the budget is not an overrun", func(t *testing.T) {
		t.Parallel()
		b := newEvalBudget()
		for range maxRuleOverruns * 2 {
			b.record("borderline", maxRuleEvalNs, now)
		}
		assert.False(t, b.skipping("borderline"))
	})
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/the-other-rules-are-unaffected
//
// TestEvalBudget_SkipsOneRuleNotTheRest pins that the budget is per rule. A bound that stopped the whole catalog because one rule
// was expensive would trade a slow deployment for a blind one.
func TestEvalBudget_SkipsOneRuleNotTheRest(t *testing.T) {
	t.Parallel()
	now := time.Now()
	b := newEvalBudget()

	for range maxRuleOverruns {
		b.record("expensive", overBudget, now)
	}
	require.True(t, b.skipping("expensive"))
	assert.False(t, b.skipping("cheap"), "a rule that has never run over budget must be untouched")

	skipped := b.Skipped()
	require.Len(t, skipped, 1)
	rec := skipped["expensive"]
	assert.Equal(t, overBudget, rec.worstNs, "the surface reports what it measured, which is what an author needs")
	assert.Equal(t, maxRuleOverruns, rec.overrunsAt)
}

// TestEvalBudget_ConcurrentRecordersAgree is the -race half. Evaluate runs from concurrent workers (issue #535), so the budget is
// written by several at once while every batch reads the skip set per rule.
func TestEvalBudget_ConcurrentRecordersAgree(t *testing.T) {
	t.Parallel()
	b := newEvalBudget()
	now := time.Now()

	var wg sync.WaitGroup
	var transitions int64
	var mu sync.Mutex
	for range 8 {
		wg.Go(func() {
			for range maxRuleOverruns {
				if exhausted, _ := b.record("contended", overBudget, now); exhausted {
					mu.Lock()
					transitions++
					mu.Unlock()
				}
				_ = b.skipping("contended")
			}
		})
	}
	wg.Wait()

	assert.True(t, b.skipping("contended"))
	assert.Equal(t, int64(1), transitions,
		"exactly one worker may report the transition, or an operator sees the same rule announced eight times")
}

// slowRule takes longer than the budget and counts how often it was invoked, which is how the skip is observed from outside.
type slowRule struct {
	stubRule
	mu    sync.Mutex
	calls int
	sleep time.Duration
}

func (r *slowRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	time.Sleep(r.sleep)
	return nil, nil
}

func (r *slowRule) invocations() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/an-overrun-does-not-cause-the-batch-to-be-replayed
// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-rule-repeatedly-over-budget-stops-being-evaluated
//
// TestEngine_Evaluate_OverBudgetRuleIsSkippedWithoutFailingTheBatch drives the whole path, and the batch assertion is the one that
// matters most.
//
// The trap this pins is in the code above it: in Evaluate, a rule error that does not wrap ErrRetryBatch returns from the batch,
// and the processor then nacks and replays it. A slow rule reporting failure would therefore be retried into the same slow rule on
// every attempt, which is exactly the stalled host #836 exists to prevent, reached by a different route. So every batch here must
// succeed, including the ones where the rule ran over budget.
//
// The budget is driven directly rather than by sleeping past 100ms twenty times, which would make this test take two seconds to
// assert something the record test already covers. What is exercised here is the engine: that a rule marked skipped stops being
// invoked, and that nothing about the overrun reaches the caller as an error.
func TestEngine_Evaluate_OverBudgetRuleIsSkippedWithoutFailingTheBatch(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	rule := &slowRule{stubRule: stubRule{id: "slow_rule"}, sleep: time.Millisecond}
	e.Register(rule)
	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}

	// One real evaluation: it runs, and the batch succeeds.
	_, err := e.Evaluate(t.Context(), batch)
	require.NoError(t, err, "an evaluation over budget must never fail the batch")
	require.Equal(t, 1, rule.invocations())

	// Exhaust the budget the way twenty slow batches would.
	now := time.Now()
	for range maxRuleOverruns {
		e.budget.record("slow_rule", overBudget, now)
	}
	require.True(t, e.budget.skipping("slow_rule"))

	before := rule.invocations()
	for range 5 {
		_, err = e.Evaluate(t.Context(), batch)
		require.NoError(t, err, "a batch carrying only a skipped rule must still succeed")
	}
	assert.Equal(t, before, rule.invocations(), "a skipped rule must not be invoked again on this replica")
}

// TestEngine_Evaluate_SkippingOneRuleLeavesTheOthersRunning is the other half: a bound that stopped the whole catalog because one
// rule was expensive would trade a slow deployment for a blind one.
func TestEngine_Evaluate_SkippingOneRuleLeavesTheOthersRunning(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	slow := &slowRule{stubRule: stubRule{id: "slow_rule"}}
	fine := &slowRule{stubRule: stubRule{id: "fine_rule"}}
	e.Register(slow)
	e.Register(fine)

	now := time.Now()
	for range maxRuleOverruns {
		e.budget.record("slow_rule", overBudget, now)
	}

	_, err := e.Evaluate(t.Context(), []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}})
	require.NoError(t, err)

	assert.Zero(t, slow.invocations(), "the skipped rule must not run")
	assert.Equal(t, 1, fine.invocations(), "and every other rule must, or one expensive rule blinds the deployment")
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/an-overrun-does-not-cause-the-batch-to-be-replayed
//
// TestEngine_Evaluate_ARealOverrunIsRecordedAndNotReturned closes the gap review found in the test above it: that one drove the
// budget bookkeeping directly, so the branch in evaluateRule's defer was never entered and a mutation reporting an overrun as an
// error would have survived.
//
// Here the rule is genuinely slower than the budget, which is lowered rather than waiting out 100ms twenty times. That exercises
// the real path: the overrun is recorded, the batch still succeeds, and the rule stops being evaluated once the count is reached.
//
// One thing this does NOT cover, stated because mutation testing showed it: charging the budget the FULL evaluateRule duration
// instead of the rule's own survives every test here. It cannot fail one, because these run against a nil store, so alert
// persistence does nothing and the two durations are equal by construction. Making them differ needs a real store and a
// deterministically slow write, which is a harness worth more than the guard it would add. What holds the distinction is that
// ruleElapsed is measured around exactly one call, the rule's own Evaluate, and the comment there says why.
func TestEngine_Evaluate_ARealOverrunIsRecordedAndNotReturned(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	// A budget below the rule's own sleep, so every evaluation is a real overrun measured by the engine.
	e.budget = newEvalBudgetWith(int64(time.Millisecond))
	rule := &slowRule{stubRule: stubRule{id: "genuinely_slow"}, sleep: 3 * time.Millisecond}
	e.Register(rule)
	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}

	for range maxRuleOverruns {
		_, err := e.Evaluate(t.Context(), batch)
		require.NoError(t, err, "an overrun must never reach the caller as an error, or the batch is nacked and retried into it")
	}

	assert.True(t, e.budget.skipping("genuinely_slow"), "twenty real overruns must exhaust the budget")
	assert.Equal(t, maxRuleOverruns, rule.invocations(), "and every one of those evaluations must have actually run")

	before := rule.invocations()
	_, err := e.Evaluate(t.Context(), batch)
	require.NoError(t, err)
	assert.Equal(t, before, rule.invocations(), "after which it is skipped")
}

// recordingSkips answers "was the transition reported". It records the one method the skip path is about and stubs the other the
// evaluation path calls; the rest stay absent, which is safe only for methods the engine does not reach. Embedding an interface
// makes that a runtime nil dereference rather than a compile error, so a new call on the evaluation path has to be stubbed here
// deliberately (issue #837 added one).
type recordingSkips struct {
	api.MetricsRecorder
	mu      sync.Mutex
	skipped []string
}

func (r *recordingSkips) RuleEvaluationSkipped(_ context.Context, ruleID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skipped = append(r.skipped, ruleID)
}
func (r *recordingSkips) RuleEvaluationDuration(context.Context, string, time.Duration) {}

func (r *recordingSkips) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.skipped...)
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-rule-repeatedly-over-budget-stops-being-evaluated
//
// TestEngine_Evaluate_ReportsTheSkipOnceThroughTheRecorder closes a gap review found: the transition was asserted through the
// budget's own return value, and nothing checked that the engine actually told the recorder.
//
// It matters because a skipped rule raises no alerts, which looks exactly like a rule that matches nothing. This counter is the
// only thing separating the two, so an engine that skipped the rule and reported nothing would be the silent failure the whole
// design exists to avoid. Once, not per batch: a rule that costs nothing because it is skipped must not read as the busiest thing
// in the fleet.
func TestEngine_Evaluate_ReportsTheSkipOnceThroughTheRecorder(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	e.budget = newEvalBudgetWith(int64(time.Millisecond))
	rec := &recordingSkips{}
	e.SetMetrics(rec)
	e.Register(&slowRule{stubRule: stubRule{id: "announced"}, sleep: 3 * time.Millisecond})

	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}
	for range maxRuleOverruns * 2 {
		_, err := e.Evaluate(t.Context(), batch)
		require.NoError(t, err)
	}

	require.True(t, e.budget.skipping("announced"))
	assert.Equal(t, []string{"announced"}, rec.names(),
		"the transition must be reported exactly once, naming the rule an operator has to fix")
}

// TestEngine_LoadActive_ForgetsWhatTheBudgetLearned covers the interaction with #850's reloadable rule content.
//
// The skip is keyed by rule id, so without clearing it an operator who fixes a slow rule and publishes it under the same id gets
// the corrected rule installed and never evaluated. The heuristic would be punishing a rule that no longer exists, and the only
// way out would be a restart.
func TestEngine_LoadActive_ForgetsWhatTheBudgetLearned(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	fixed := &slowRule{stubRule: stubRule{id: "was_slow"}}
	e.Register(fixed)

	now := time.Now()
	for range maxRuleOverruns {
		e.budget.record("was_slow", maxRuleEvalNs+1, now)
	}
	require.True(t, e.budget.skipping("was_slow"))

	// The operator publishes a corrected rule under the same id, which #850's refresh loop installs through here.
	e.LoadActive(staticProvider{rules: []rulesapi.Rule{fixed}})

	assert.False(t, e.budget.skipping("was_slow"), "a new rule set must get a fresh judgement")

	// And a run that had NOT yet reached the bound must be cleared too, not just the completed skips. A rule sitting on
	// nineteen overruns would otherwise be skipped by its first overrun after the reload, which is the same bug with a smaller
	// number: the judgement would still be about the rule that was replaced.
	partial := &slowRule{stubRule: stubRule{id: "nearly_slow"}}
	e.Register(partial)
	for range maxRuleOverruns - 1 {
		e.budget.record("nearly_slow", maxRuleEvalNs+1, now)
	}
	e.LoadActive(staticProvider{rules: []rulesapi.Rule{fixed, partial}})
	e.budget.record("nearly_slow", maxRuleEvalNs+1, now)
	assert.False(t, e.budget.skipping("nearly_slow"),
		"one overrun after a reload must not finish a run the previous rule set started")

	_, err := e.Evaluate(t.Context(), []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}})
	require.NoError(t, err)
	assert.Equal(t, 1, fixed.invocations(), "and the corrected rule must actually run")
}

// staticProvider is the minimal shape LoadActive accepts.
type staticProvider struct{ rules []rulesapi.Rule }

func (p staticProvider) ActiveRules() []rulesapi.Rule { return p.rules }

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-skipped-rule-reports-its-configured-mode-unchanged
//
// TestEvalBudget_DoesNotTouchTheRuleSet pins the design decision this change turns on, which review noted had no test.
//
// A rule's mode is what the operator asked for; a skip is what the server is doing to protect itself. Reporting one as the other
// would have the catalog claim a rule was disabled by someone who never touched it, and leave unclear who may undo it. So the
// budget owns a set of ids and nothing else: it does not reach into the rule set, the resolved modes, or anything an operator
// reads as configuration.
//
// Asserted structurally, because that is what makes it durable. A future change that "helpfully" flipped the mode would have to
// give the budget a way to reach it, and this test is what says the budget has no such reach by construction.
func TestEvalBudget_DoesNotTouchTheRuleSet(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	rule := &slowRule{stubRule: stubRule{id: "over_budget"}}
	e.Register(rule)

	before := e.active.Load()
	require.Len(t, before.rules, 1)

	now := time.Now()
	for range maxRuleOverruns {
		e.budget.record("over_budget", maxRuleEvalNs+1, now)
	}
	require.True(t, e.budget.skipping("over_budget"), "the rule must actually be skipped, or this asserts nothing")

	after := e.active.Load()
	assert.Same(t, before, after, "exhausting a budget must not replace the rule set")
	require.Len(t, after.rules, 1, "and must not remove the rule from it")
	assert.Equal(t, "over_budget", after.rules[0].ID(),
		"the rule stays registered and keeps reporting whatever mode the operator configured; only this replica stops running it")
}

// slowReadingRule spends its time WAITING on the graph rather than working, which is what the budget must not charge it for.
type slowReadingRule struct {
	stubRule
}

func (r *slowReadingRule) Evaluate(ctx context.Context, _ []api.Event, gr rulesapi.GraphReader) ([]api.Finding, error) {
	_, _ = gr.GetProcessByPID(ctx, "host-a", 1, 0)
	return nil, nil
}

// slowGraphReader is a reader whose every call takes a while, standing in for a database under load.
type slowGraphReader struct {
	stubGraphReader
	delay time.Duration
}

func (r slowGraphReader) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	time.Sleep(r.delay)
	return nil, nil
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/a-rule-slowed-only-by-the-datastore-is-not-skipped
//
// TestEngine_Evaluate_TimeWaitingOnTheGraphIsNotCharged covers the correction review forced twice.
//
// The budget first charged the whole evaluateRule call, including alert persistence. Fixed, it still charged the rule's reads,
// which are synchronous MySQL: a slow database would then disable rules rather than slow rules, worst first among the rules doing
// the most correlation, at exactly the moment detections matter most. What is left is the rule's own matching, which is the thing
// an author controls.
func TestEngine_Evaluate_TimeWaitingOnTheGraphIsNotCharged(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	// A budget far below the read delay, so a rule charged for its reads would be skipped almost immediately.
	e.budget = newEvalBudgetWith(int64(time.Millisecond))
	e.ruleReader = &retryableGraphReader{inner: slowGraphReader{delay: 5 * time.Millisecond}}
	rule := &slowReadingRule{stubRule: stubRule{id: "reads_a_lot"}}
	e.Register(rule)

	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}
	for range maxRuleOverruns * 2 {
		_, err := e.Evaluate(t.Context(), batch)
		require.NoError(t, err)
	}

	assert.False(t, e.budget.skipping("reads_a_lot"),
		"a rule that is slow only because the graph is slow must not be disabled; that punishes the database, not the rule")
}

// TestEvalBudget_InBudgetEvaluationDoesNotTakeTheLock pins the property review asked for after finding that clearing a rule's
// overrun run held the single mutex on the one path that always runs, serializing every ingestion worker once per evaluated rule.
//
// The assertion is direct rather than a benchmark: the test HOLDS the mutex and requires record to return anyway. A record that
// reaches for the lock cannot finish, so the deadline is what fails, and the test measures the property (this path does not
// acquire mu) rather than a timing proxy for it.
func TestEvalBudget_InBudgetEvaluationDoesNotTakeTheLock(t *testing.T) {
	t.Parallel()

	b := newEvalBudgetWith(int64(10 * time.Millisecond))

	b.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		exhausted, worst := b.record("rule.fast", int64(time.Millisecond), time.Now())
		assert.False(t, exhausted)
		assert.Zero(t, worst)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		b.mu.Unlock()
		t.Fatal("an in-budget evaluation blocked on the overrun lock; the hot path must not acquire it")
	}
	b.mu.Unlock()
}

// TestEvalBudget_ClearingStillWorksWhenARunExists is the other half of the lock-free gate above: skipping the lock is only correct
// while there is nothing to clear, so once a run exists an in-budget evaluation must still clear it and the gate must reopen.
func TestEvalBudget_ClearingStillWorksWhenARunExists(t *testing.T) {
	t.Parallel()

	budgetNs := int64(10 * time.Millisecond)
	b := newEvalBudgetWith(budgetNs)
	now := time.Now()

	// One overrun opens a run, which the gate must then observe.
	b.record("rule.slow", budgetNs+1, now)
	require.Equal(t, int64(1), b.activeRuns.Load(), "an overrun must publish its run to the lock-free gate")

	// An evaluation inside the budget clears it, and the gate closes again.
	b.record("rule.slow", 1, now.Add(time.Second))
	require.Equal(t, int64(0), b.activeRuns.Load(), "clearing the last run must close the gate")

	// The cleared run means the count restarts, so the rule is not skipped by the overruns that preceded the clear.
	for i := range maxRuleOverruns - 1 {
		exhausted, _ := b.record("rule.slow", budgetNs+1, now.Add(time.Duration(i+2)*time.Second))
		require.False(t, exhausted, "overrun %d must not exhaust the budget after a clear reset the count", i+1)
	}
	assert.False(t, b.skipping("rule.slow"))

	// A reload discards the runs, so the gate must close with them. Mutation testing found this one: leaving it open is not a
	// correctness bug, since the first in-budget evaluation republishes the real length, but it puts every worker back through
	// the lock in the meantime, and a reload happens on a timer.
	require.Positive(t, b.activeRuns.Load(), "the loop above must leave a run open for forget to clear")
	b.forget()
	assert.Zero(t, b.activeRuns.Load(), "forget must close the lock-free gate along with the runs it discards")
}

// lendingRule hands its reader to a later rule, which is what the Sigma adapter's batch memo does in production.
type lendingRule struct {
	stubRule
	lent chan rulesapi.GraphReader
}

func (r *lendingRule) Evaluate(_ context.Context, _ []api.Event, gr rulesapi.GraphReader) ([]api.Finding, error) {
	// Deliberately does NOT read. In production the first rule to see an event builds the memo and may never resolve it; the
	// lookups are lazy, so the read happens whenever some later rule first asks.
	select {
	case r.lent <- gr:
	default:
	}
	return nil, nil
}

// borrowingRule reads through the EARLIER rule's reader while passing its OWN context, which is exactly the shape the memo
// produces: the closure holds the reader of whichever rule built it, and sigmaEvent rebinds the context per rule.
type borrowingRule struct {
	stubRule
	lent chan rulesapi.GraphReader
}

func (r *borrowingRule) Evaluate(ctx context.Context, _ []api.Event, own rulesapi.GraphReader) ([]api.Finding, error) {
	select {
	case borrowed := <-r.lent:
		_, _ = borrowed.GetProcessByPID(ctx, "host-a", 1, 0)
	default:
		_, _ = own.GetProcessByPID(ctx, "host-a", 1, 0)
	}
	return nil, nil
}

// spec:server-detection-rules-engine/a-rule-that-repeatedly-exceeds-its-evaluation-budget-stops-being-evaluated/waiting-is-charged-to-the-rule-that-triggered-the-read
//
// TestEngine_Evaluate_WaitingIsChargedToTheRuleThatTriggeredTheRead pins the attribution bug the second review round found.
//
// The Sigma adapter memoizes each event's graph lookups for the whole batch, and those closures capture the api.GraphReader
// belonging to whichever rule BUILT the memo, while the context is rebound to whichever rule INVOKES them. So a read triggered by
// a later rule ran through an earlier rule's reader. When the wait total lived on the reader, it was credited to the earlier rule,
// whose evaluation had already finished and whose total was discarded, and the rule that actually waited was left with zero
// subtracted. The slow database it waited on was charged to it after all, and could still get it skipped.
//
// Reproduced here without the catalog package, by having one rule lend its reader to a later one, because the property is about
// the engine: a read made with rule B's context must be subtracted from B whichever reader instance performs it.
func TestEngine_Evaluate_WaitingIsChargedToTheRuleThatTriggeredTheRead(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	// Far below the read delay, so a rule charged for the read is skipped almost at once.
	e.budget = newEvalBudgetWith(int64(time.Millisecond))
	e.ruleReader = &retryableGraphReader{inner: slowGraphReader{delay: 5 * time.Millisecond}}

	lent := make(chan rulesapi.GraphReader, 1)
	// Registered in this order so the lender is evaluated first and the borrower reads through the reader it was handed.
	e.Register(&lendingRule{stubRule: stubRule{id: "builds_the_memo"}, lent: lent})
	e.Register(&borrowingRule{stubRule: stubRule{id: "triggers_the_read"}, lent: lent})

	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}
	for range maxRuleOverruns * 2 {
		_, err := e.Evaluate(t.Context(), batch)
		require.NoError(t, err)
	}

	assert.False(t, e.budget.skipping("triggers_the_read"),
		"the rule that waited on the graph must have that wait subtracted even though another rule's reader performed it")
	assert.False(t, e.budget.skipping("builds_the_memo"),
		"and the rule that merely built the memo must not be charged for a read it never asked for")
}

// recordingDurations captures what the histogram is told, so a test can assert the QUANTITY rather than only that a method was
// called. Embeds the interface for the methods the engine does not reach on this path; see countingMetrics for why that is a trap
// worth knowing about.
type recordingDurations struct {
	api.MetricsRecorder
	mu   sync.Mutex
	seen map[string]time.Duration
}

func (r *recordingDurations) RuleEvaluationDuration(_ context.Context, ruleID string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Duration{}
	}
	r.seen[ruleID] = max(r.seen[ruleID], d)
}

func (r *recordingDurations) RuleEvaluationSkipped(context.Context, string) {}

func (r *recordingDurations) worst(ruleID string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[ruleID]
}

// spec:server-detection-rules-engine/evaluation-statistics-are-aggregated-in-process-and-written-periodically/evaluation-duration-is-available-as-a-histogram-per-rule
//
// TestEngine_Evaluate_HistogramIncludesGraphReadTime pins the one place the histogram and the budget deliberately disagree, which
// review asked for after an earlier cut had them agree.
//
// The budget subtracts graph-read time so a slow datastore cannot disable rules. The histogram must NOT, because it is what an
// operator reads to ask which rule is slow, and a rule that is slow through its reads is exactly as much of an operator problem
// as one slow through matching. It also has to agree with the durable table, which records the full duration.
//
// Asserted together in one test because the pair is the point: the same evaluation must be visible to the histogram and invisible
// to the skip.
func TestEngine_Evaluate_HistogramIncludesGraphReadTime(t *testing.T) {
	t.Parallel()

	const readDelay = 5 * time.Millisecond
	e := New(nil, nil)
	// A budget far below the read delay, so a rule charged for its reads would be skipped almost immediately.
	e.budget = newEvalBudgetWith(int64(time.Millisecond))
	e.ruleReader = &retryableGraphReader{inner: slowGraphReader{delay: readDelay}}
	rec := &recordingDurations{}
	e.SetMetrics(rec)
	e.Register(&slowReadingRule{stubRule: stubRule{id: "reads_a_lot"}})

	batch := []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}}
	for range maxRuleOverruns * 2 {
		_, err := e.Evaluate(t.Context(), batch)
		require.NoError(t, err)
	}

	assert.GreaterOrEqual(t, rec.worst("reads_a_lot"), readDelay,
		"the histogram must include the time spent waiting on the graph, or it answers a different question from the table")
	assert.False(t, e.budget.skipping("reads_a_lot"),
		"and the budget must still exclude it, or a slow datastore disables rules rather than slow rules doing so")
}
