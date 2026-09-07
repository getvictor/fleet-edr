package main

import (
	"bytes"
	"errors"
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

// A retirement archived on an EARLIER date does not excuse the loss: the restatement came after and re-created the requirement,
// so its scenarios should be canonical. This is the ordering hazard seen from the other end.
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

// Within ONE batch the order is not recoverable, so a retirement and a restatement stamped the same date mean "cannot tell", and
// cannot-tell has to be silence.
//
// This is the case review found, with the real pair that will hit it: `latch-dns-proxy-bypass` restates a requirement and
// `dns-proxy-no-bypass` retires it, both pending, so both archive on the same day. Comparing folder NAMES put the remover first
// alphabetically and reported a correct retirement as a loss. A false positive costs more than a missed one here, because the
// whole procedure is a reader comparing two lists and noticing what is new.
func TestVerifyArchive_SameBatchIsNotGuessedAt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, remover string }{
		{"the remover sorts first", "2026-09-07-dns-proxy-no-bypass"},
		{"the remover sorts last", "2026-09-07-zzz-retires-it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, verifyArchive(
				map[string][]archivedRestatement{
					"cap/the-thing": {{change: "2026-09-07-latch-dns-proxy-bypass", scenarios: []string{"one"}}},
				},
				map[string]map[string]struct{}{},
				map[string]string{"cap/the-thing": tc.remover},
			), "same date means the order is unknown, and an unknown is not a finding")
		})
	}
}

func TestArchiveDate(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "2026-06-09", archiveDate("2026-06-09-some-change"))
	// The malformed double-date folders that predate this still yield the date from their first ten characters.
	assert.Equal(t, "2026-06-09", archiveDate("2026-06-09-2026-06-09-dns-proxy-on-by-default"))
	assert.Equal(t, "short", archiveDate("short"))
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

	// Findings do not gate, but a report that could not be written does. The procedure is a release engineer diffing this
	// output against the run from before archiving, so a list truncated by a broken pipe and reported as success would hide
	// the one new line the diff exists to surface.
	t.Run("a truncated report is a failure, not a clean run", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 2, printArchiveVerify(&stubbornWriter{ok: 1, err: errors.New("pipe closed")},
			[]string{"cap/r/s\n    listed by x"}, 3))
	})

	// The clean path writes too, and its single line is just as capable of failing.
	t.Run("a truncated clean report is a failure too", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 2, printArchiveVerify(&stubbornWriter{err: errors.New("pipe closed")}, nil, 12))
	})
}
