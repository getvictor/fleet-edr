package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func canonicalWith(requirement string, scenarios ...string) map[string]map[string]struct{} {
	set := make(map[string]struct{}, len(scenarios))
	for _, s := range scenarios {
		set[s] = struct{}{}
	}
	return map[string]map[string]struct{}{requirement: set}
}

// The loss this exists to detect: a restatement named a scenario that is not in the canonical spec, so something replaced the
// requirement with an older body after that restatement was applied.
func TestVerifyArchive_ReportsAScenarioTheCanonicalSpecLacks(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-02-refines-it", scenarios: []string{"kept", "lost"}}},
		},
		canonicalWith("cap/the-thing", "kept"),
		nil,
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing/lost")
	assert.Contains(t, findings[0], "2026-06-02-refines-it")
}

func TestVerifyArchive_SaysNothingWhenEveryScenarioSurvived(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-02-refines-it", scenarios: []string{"one", "two"}}},
		},
		canonicalWith("cap/the-thing", "one", "two"),
		nil,
	))
}

// The LAST restatement is the authority, so a scenario an earlier one named and a later one dropped is a retirement rather than
// a loss. This is the half the check can do; within one archive batch the order is not recoverable, which is why the command
// reports rather than gates and the checklist reads it as a before-and-after.
func TestVerifyArchive_TheLastRestatementIsTheAuthority(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {
				{change: "2026-06-02-first", scenarios: []string{"one", "retired-later"}},
				{change: "2026-06-09-second", scenarios: []string{"one"}},
			},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
	))
}

// A requirement a later change retired legitimately has nothing canonical left, and reporting every one of its scenarios as lost
// would bury a real finding under every retirement the project has ever made.
func TestVerifyArchive_ARetiredRequirementIsNotALoss(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-02-refines-it", scenarios: []string{"one"}}},
		},
		map[string]map[string]struct{}{},
		map[string]string{"cap/the-thing": "2026-06-09-retires-it"},
	))
}

// A retirement archived BEFORE the restatement does not excuse the loss: the restatement re-created the requirement, so its
// scenarios should be canonical. This is the ordering hazard seen from the other end.
func TestVerifyArchive_AnEarlierRetirementDoesNotExcuseIt(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-09-refines-it", scenarios: []string{"one"}}},
		},
		map[string]map[string]struct{}{},
		map[string]string{"cap/the-thing": "2026-06-02-retires-it"},
	)
	assert.Len(t, findings, 1)
}

func TestPrintArchiveVerify(t *testing.T) {
	t.Parallel()

	t.Run("says so when nothing is missing", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 0, printArchiveVerify(&buf, nil, 12))
		assert.Contains(t, buf.String(), "every scenario still canonical")
	})

	// Exit 0 even with findings, because the tree carries pre-existing entries this pass cannot classify and a command that
	// fails from the day it lands is one somebody adds a skip for. The checklist reads it by difference.
	t.Run("reports without gating, and says how to read it", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 0, printArchiveVerify(&buf, []string{"cap/r/s\n    listed by x"}, 3))
		out := buf.String()
		assert.Contains(t, out, "A line that is NEW is a scenario this archive")
		assert.Contains(t, out, "cap/r/s")
	})
}
