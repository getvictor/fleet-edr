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
