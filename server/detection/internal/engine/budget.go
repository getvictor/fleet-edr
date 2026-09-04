package engine

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"
)

// maxRuleEvalNs is how long one rule may take to evaluate one batch before the evaluation counts as an overrun.
//
// Set from measured per-rule statistics rather than chosen. Across 219 evaluations of the vendored corpus on dev traffic the mean
// evaluation was 0.094ms and the slowest rule doing legitimate work took 17.8ms
// (proc_creation_macos_remote_access_tools_teamviewer_incoming_connection); the next slowest took 1.24ms. A pattern sitting at the
// per-pattern cost limit #852 introduced runs about 4ms per event, and a batch is up to 100 events, so an unaffordable rule reaches
// roughly 400ms per batch.
//
// 100ms therefore sits about 5.6x above the slowest legitimate rule, three orders above the mean, and well below where an
// unaffordable rule lands. Same reasoning as maxConditionDepth: far above real content, far below where it hurts.
const maxRuleEvalNs = int64(100 * time.Millisecond)

// Two bounds, both required, following issue #836. A single overrun is not evidence: a cold cache, an unusually large batch, or a
// host that just enrolled each produce one, and the 17.8ms measured above came from a rule whose only two evaluations were both
// slow, which is the shape a small sample produces.
//
// 20 overruns bounds the wasted work before a skip to roughly two seconds. The window makes the count mean "repeatedly, lately"
// rather than "eventually": without it a rule that ran slow twenty times over a month would be skipped on the strength of a
// condition that has long passed.
//
// The window is FIXED from the first overrun of a run, not sliding, which review asked about and which is the deliberate choice.
// Nineteen overruns just inside a window and one just outside it start a fresh run rather than tripping the bound, so a rule has
// to be consistently over budget within one window to be skipped. A sliding window would trip on that pattern, and would need the
// timestamps of every overrun rather than a count and a start.
const (
	maxRuleOverruns   = 20
	ruleOverrunWindow = 15 * time.Minute
)

// evalBudget tracks which rules have exhausted their evaluation budget on THIS replica.
//
// Per-replica in-process state, and safe to lose in ADR-0010's sense: it holds nothing a peer would need to serve the next request,
// each replica measures the load it actually sees, and a restart clears it. That last part is deliberate rather than incidental. A
// heuristic that survived a restart would keep punishing a rule for a condition that may have passed, and the cheapest way to
// re-test the rule is to let the next process try it.
//
// Reads happen once per rule per batch and writes only when an evaluation is over budget, which is why the skip set is an atomic
// pointer read without a lock while the overrun bookkeeping sits behind a mutex.
type evalBudget struct {
	// budgetNs is maxRuleEvalNs in production and lowered by tests, so an over-budget evaluation can be driven by a rule that is
	// actually slow rather than by poking the bookkeeping. Review found the gap that motivated this: a fixture sleeping 1ms
	// against a 100ms budget never entered the overrun branch at all, so a mutation that reported an overrun as an error (the
	// failure mode this whole design exists to avoid) survived the test that was supposed to cover it.
	budgetNs int64
	// skipped is the set of rule ids this replica has stopped evaluating, replaced wholesale so a reader never holds a lock.
	skipped atomic.Pointer[map[string]skipRecord]

	mu sync.Mutex
	// overruns counts recent overruns per rule. Only touched when an evaluation exceeds the budget.
	overruns map[string]*overrunRun
}

// skipRecord is what a skip reports about itself: enough for an operator to see which rule stopped and how badly it was over.
type skipRecord struct {
	at         time.Time
	worstNs    int64
	overrunsAt int
}

// overrunRun is a rule's recent overruns: how many, and when the run started, which is what makes the window meaningful.
type overrunRun struct {
	count   int
	first   time.Time
	worstNs int64
}

func newEvalBudget() *evalBudget { return newEvalBudgetWith(maxRuleEvalNs) }

func newEvalBudgetWith(budgetNs int64) *evalBudget {
	b := &evalBudget{budgetNs: budgetNs, overruns: map[string]*overrunRun{}}
	empty := map[string]skipRecord{}
	b.skipped.Store(&empty)
	return b
}

// skipping reports whether this replica has stopped evaluating the rule. One atomic load, on the path that runs per rule per batch.
func (b *evalBudget) skipping(ruleID string) bool {
	_, ok := (*b.skipped.Load())[ruleID]
	return ok
}

// record notes one evaluation's elapsed time and reports whether THIS evaluation is what exhausted the rule's budget, so the caller
// logs and counts the transition once rather than on every subsequent overrun.
//
// An evaluation inside the budget clears the run. That is what makes the count mean "repeatedly" rather than "ever": a rule that is
// occasionally slow and usually fine never accumulates, and only a rule that is consistently over budget reaches the bound.
func (b *evalBudget) record(ruleID string, elapsedNs int64, now time.Time) (exhausted bool, worstNs int64) {
	if elapsedNs <= b.budgetNs {
		b.mu.Lock()
		delete(b.overruns, ruleID)
		b.mu.Unlock()
		return false, 0
	}

	b.mu.Lock()
	run, ok := b.overruns[ruleID]
	if !ok || now.Sub(run.first) > ruleOverrunWindow {
		// Either the first overrun, or the previous run is older than the window and says nothing about now.
		run = &overrunRun{first: now}
		b.overruns[ruleID] = run
	}
	run.count++
	if elapsedNs > run.worstNs {
		run.worstNs = elapsedNs
	}
	reached := run.count >= maxRuleOverruns
	worst := run.worstNs
	count := run.count
	if reached {
		delete(b.overruns, ruleID)
	}
	b.mu.Unlock()

	if !reached {
		return false, worst
	}
	return b.markSkipped(ruleID, skipRecord{at: now, worstNs: worst, overrunsAt: count}), worst
}

// markSkipped adds the rule to the skip set, copy-on-write so a concurrent skipping() never sees a partially built map. Reports
// false when another worker got there first, so only one caller logs the transition.
func (b *evalBudget) markSkipped(ruleID string, rec skipRecord) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := *b.skipped.Load()
	if _, already := current[ruleID]; already {
		return false
	}
	next := make(map[string]skipRecord, len(current)+1)
	maps.Copy(next, current)
	next[ruleID] = rec
	b.skipped.Store(&next)
	return true
}

// forget clears everything this budget has learned, which a new rule set requires.
//
// Review found the interaction: the skip is keyed by rule id, and #850 made rule content reloadable while the server runs. Without
// this, an operator who fixes a slow rule and publishes it under the same id gets the corrected version installed and never
// evaluated, because the id is still in the skip set. The heuristic would then be punishing a rule that no longer exists.
//
// Cleared wholesale rather than per changed rule: the engine is handed a whole set and does not diff it, and a rule whose id
// survived a reload may still have a changed body. Re-learning costs at most one window of overruns per genuinely slow rule, which
// is the same cost a restart already carries and for the same reason.
func (b *evalBudget) forget() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.overruns = map[string]*overrunRun{}
	empty := map[string]skipRecord{}
	b.skipped.Store(&empty)
}

// Skipped reports what this replica has stopped evaluating, for the operator-facing surface. Copied so a caller cannot mutate the
// live set.
func (b *evalBudget) Skipped() map[string]skipRecord {
	current := *b.skipped.Load()
	out := make(map[string]skipRecord, len(current))
	maps.Copy(out, current)
	return out
}
