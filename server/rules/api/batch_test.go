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
	s.RecordAncestryIncomplete("suspicious_exec")
	s.RecordAncestryIncomplete("shell_network_connect")
	s.RecordAncestryIncomplete("suspicious_exec")

	assert.Equal(t, map[string]int{"suspicious_exec": 2, "shell_network_connect": 1}, s.AncestryIncompleteCounts())
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
	assert.NotPanics(t, func() { s.RecordAncestryIncomplete("suspicious_exec") })
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
