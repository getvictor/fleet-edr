package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBatchScopeRecordsDeclinesPerRule pins that the count is keyed by rule id rather than pooled for the batch.
//
// One scope is shared by every rule in a batch, and the engine reads a single key from it to annotate a span already labelled with
// that rule's id. If the counts were pooled, two rules sharing the exec-chain walk would each report the other's declines and the
// number an operator compares against one rule's alert volume would be wrong in a way nothing else reveals.
func TestBatchScopeRecordsDeclinesPerRule(t *testing.T) {
	t.Parallel()

	var s BatchScope
	// Distinct shells, so nothing here is absorbed by the per-shell dedup the test below covers.
	s.RecordAncestryIncomplete("suspicious_exec", 100)
	s.RecordAncestryIncomplete("shell_network_connect", 100)
	s.RecordAncestryIncomplete("suspicious_exec", 200)

	assert.Equal(t, map[string]int{"suspicious_exec": 2, "shell_network_connect": 1}, s.AncestryIncompleteCounts())
}

// TestBatchScopeCountsEachDeclinedShellOnce pins the dedup that keeps the count comparable to alert volume.
//
// Findings are deduped per shell, so one unresolved chain costs at most one alert no matter how many trigger events reach it. The
// count is specified to be read against that alert volume, so counting once per trigger event instead would report several
// declines against at most one lost alert: a shell that a batch happened to touch five times would read as five lost detections.
// Note the same shell pid IS counted separately per rule, because the two rules decline independently and each is compared against
// its own alerts.
func TestBatchScopeCountsEachDeclinedShellOnce(t *testing.T) {
	t.Parallel()

	var s BatchScope
	for range 5 {
		s.RecordAncestryIncomplete("suspicious_exec", 100)
	}
	s.RecordAncestryIncomplete("suspicious_exec", 101)
	s.RecordAncestryIncomplete("shell_network_connect", 100)

	assert.Equal(t, map[string]int{"suspicious_exec": 2, "shell_network_connect": 1}, s.AncestryIncompleteCounts(),
		"five triggers on shell 100 count once; shell 101 is a second distinct chain; the other rule counts its own")
}

// TestBatchScopeIsNilSafe pins the nil-receiver contract both methods document.
//
// It is load-bearing rather than defensive: a rule's Evaluate entry point is reached by the replay harness and by fixtures without
// the engine's scope, and the ScopedRule contract is that a rule behaves identically either way. If recording an observation
// panicked on a nil scope, adding an observation to a rule would break every caller that does not run through the engine, which is
// most of the test suite and the whole fixture corpus.
func TestBatchScopeIsNilSafe(t *testing.T) {
	t.Parallel()

	var s *BatchScope
	assert.NotPanics(t, func() { s.RecordAncestryIncomplete("suspicious_exec", 100) })
	assert.Nil(t, s.AncestryIncompleteCounts(), "nothing was recorded, so there is nothing to report")
}

// TestBatchScopeReportsNilBeforeAnythingIsDeclined separates "no declines" from "not tracking", which the engine relies on: it
// indexes the returned map directly, and a nil map indexes to zero rather than panicking, so the span reports an honest 0 for the
// overwhelmingly common batch where every chain resolved.
func TestBatchScopeReportsNilBeforeAnythingIsDeclined(t *testing.T) {
	t.Parallel()

	var s BatchScope
	assert.Nil(t, s.AncestryIncompleteCounts())
	assert.Equal(t, 0, s.AncestryIncompleteCounts()["suspicious_exec"], "the engine indexes this map without checking it first")
}

// TestBatchScopeCountsEachAbandonedProcessOncePerRule pins the abandon counter's keying, which has to agree with how the rules that
// feed it dedupe their findings. They emit at most one finding per process, so a count per trigger event would report several
// abandons against at most one lost finding, and the ratio an operator reads against evaluations would overstate the loss.
//
// The same pid under a second rule is a SEPARATE abandon: the scope is shared by every rule in the batch, and two rules that each
// needed the same missing record each failed to decide their own event.
func TestBatchScopeCountsEachAbandonedProcessOncePerRule(t *testing.T) {
	t.Parallel()

	var s BatchScope
	s.RecordMaterializationAbandoned("dns_c2_beacon", 100)
	s.RecordMaterializationAbandoned("dns_c2_beacon", 100)
	s.RecordMaterializationAbandoned("dns_c2_beacon", 200)
	s.RecordMaterializationAbandoned("suspicious_exec", 100)

	assert.Equal(t, 2, s.MaterializationAbandoned("dns_c2_beacon"), "two distinct processes, one of them reached twice")
	assert.Equal(t, 1, s.MaterializationAbandoned("suspicious_exec"), "the same pid under another rule is that rule's own abandon")
	assert.Zero(t, s.MaterializationAbandoned("never_ran"), "a rule that recorded nothing reads zero")
}

// TestBatchScopeAbandonCounterIsNilSafe covers the callers that evaluate without a scope, the replay harness and direct callers,
// for whom recording must never be the thing that behaves differently from the engine.
func TestBatchScopeAbandonCounterIsNilSafe(t *testing.T) {
	t.Parallel()

	var s *BatchScope
	assert.NotPanics(t, func() { s.RecordMaterializationAbandoned("dns_c2_beacon", 100) })
	assert.Zero(t, s.MaterializationAbandoned("dns_c2_beacon"))
}
