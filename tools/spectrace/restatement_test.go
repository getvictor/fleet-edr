package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requirementBlock is one change's restatement of a shared requirement, parameterised so a test can vary the body and the scenario
// list independently. Those two vary independently in the defect this gate exists for.
func requirementBlock(body, extraScenario string) string {
	out := `## MODIFIED Requirements

### Requirement: Stable counter names

` + body + `

#### Scenario: Ingested events are counted by host

- **THEN** the counter is incremented
`
	if extraScenario != "" {
		out += "\n#### Scenario: " + extraScenario + "\n\n- **THEN** it is incremented\n"
	}
	return out
}

// TestFindRestatementConflicts covers the gate that keeps `openspec archive` from silently discarding a restatement.
//
// The case that matters most is "same scenarios, different body". Aligning scenario HEADINGS alone was the first attempt at this
// on #814, and review caught that it made the gate pass over a tree that still lost normative text at release, which is worse than
// leaving it visibly red. So the subtests below vary the body and the scenario list separately, and the body-only divergence is the
// one that would regress if this ever went back to comparing headings.
func TestFindRestatementConflicts(t *testing.T) {
	t.Parallel()

	const bodyA = "The system SHALL expose `edr.events.ingested` and `edr.detection.materialization_retries`."
	const bodyB = "The system SHALL expose `edr.events.ingested` and `edr.detection.monitor_matches`."

	t.Run("identical restatements are not a conflict", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "change-one", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "change-two", "observability-instrumentation", requirementBlock(bodyA, ""))

		assert.Empty(t, findRestatementConflicts(mustParseDeltas(t, changes)),
			"two changes may restate one requirement, as long as they agree on what it will say")
	})

	t.Run("a divergent body is a conflict even with identical scenarios", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "change-one", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "change-two", "observability-instrumentation", requirementBlock(bodyB, ""))

		conflicts := findRestatementConflicts(mustParseDeltas(t, changes))
		require.Len(t, conflicts, 1,
			"the scenario lists match, so a headings-only comparison would pass here while the archive still discarded one body")
		assert.Equal(t, "observability-instrumentation/stable-counter-names", conflicts[0].requirement)
		require.Len(t, conflicts[0].versions, 2)
		assert.Equal(t, []string{"change-one"}, conflicts[0].versions[0].changes)
		assert.Equal(t, []string{"change-two"}, conflicts[0].versions[1].changes)
	})

	t.Run("a divergent scenario list is a conflict", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "change-one", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "change-two", "observability-instrumentation",
			requirementBlock(bodyA, "Retries are counted"))

		assert.Len(t, findRestatementConflicts(mustParseDeltas(t, changes)), 1)
	})

	t.Run("one restatement is never a conflict", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "change-one", "observability-instrumentation", requirementBlock(bodyA, ""))

		assert.Empty(t, findRestatementConflicts(mustParseDeltas(t, changes)),
			"a requirement only one change restates archives without contention")
	})

	t.Run("changes agreeing are grouped together against the one that does not", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "agree-a", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "agree-b", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "odd-one-out", "observability-instrumentation", requirementBlock(bodyB, ""))

		conflicts := findRestatementConflicts(mustParseDeltas(t, changes))
		require.Len(t, conflicts, 1)
		require.Len(t, conflicts[0].versions, 2, "two distinct texts, not three restatements")
		// Grouped, so a report says "these two agree and that one does not" rather than listing every pair. With four
		// restatements of one requirement in this repository, the pairwise form would be unreadable.
		assert.Equal(t, []string{"agree-a", "agree-b"}, conflicts[0].versions[0].changes)
		assert.Equal(t, []string{"odd-one-out"}, conflicts[0].versions[1].changes)
	})

	t.Run("different requirements are independent", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "change-one", "observability-instrumentation", requirementBlock(bodyA, ""))
		writeChangeSpec(t, changes, "change-two", "agent-control-channel", requirementBlock(bodyB, ""))

		assert.Empty(t, findRestatementConflicts(mustParseDeltas(t, changes)),
			"the same requirement TITLE under two capabilities is two requirements, and neither is restated twice")
	})
}

// TestNormaliseRestatement pins exactly which differences are absorbed.
//
// The boundary matters in one direction only: every normalisation added here is a way for the gate to pass over two texts that
// will not both survive the archive. So it absorbs whitespace shape and nothing else, and this test is the record of that.
func TestNormaliseRestatement(t *testing.T) {
	t.Parallel()

	base := []string{"### Requirement: R", "", "Body text.", "", "#### Scenario: S", "", "- **THEN** yes"}

	t.Run("absorbs trailing whitespace, blank runs and edge blanks", func(t *testing.T) {
		t.Parallel()
		noisy := []string{"", "### Requirement: R   ", "", "", "Body text.\t", "", "#### Scenario: S", "", "", "- **THEN** yes", "", ""}
		assert.Equal(t, normaliseRestatement(base), normaliseRestatement(noisy),
			"whitespace shape cannot change what the archive writes, so it must not fail the gate")
	})

	t.Run("keeps a case difference", func(t *testing.T) {
		t.Parallel()
		other := append([]string(nil), base...)
		other[2] = "Body Text."
		assert.NotEqual(t, normaliseRestatement(base), normaliseRestatement(other),
			"a case difference is a real difference in prose, and often a typo worth surfacing")
	})

	t.Run("keeps a word difference", func(t *testing.T) {
		t.Parallel()
		other := append([]string(nil), base...)
		other[2] = "Body text, revised."
		assert.NotEqual(t, normaliseRestatement(base), normaliseRestatement(other))
	})
}

// TestDivergenceWindows pins that the report shows the point of disagreement rather than a shared prefix.
//
// This replaced truncate-from-the-start, which was useless here: Markdown in this repository is not hard-wrapped, so a
// requirement's prose is one long line and two versions typically agree for a hundred characters before differing. The report
// printed two identical-looking prefixes and told the reader nothing.
func TestDivergenceWindows(t *testing.T) {
	t.Parallel()

	t.Run("windows around the divergence in a long shared prefix", func(t *testing.T) {
		t.Parallel()
		prefix := strings.Repeat("shared ", 40)
		a, b := prefix+"ALPHA tail", prefix+"BETA tail"

		winA, winB := divergenceWindows(a, b)

		assert.Contains(t, winA, "ALPHA", "the window must contain the differing text, which is the whole point")
		assert.Contains(t, winB, "BETA")
		assert.NotEqual(t, winA, winB, "two windows that read identically tell the reader nothing")
		assert.True(t, strings.HasPrefix(winA, "..."), "a window that cut the start says so")
	})

	t.Run("reports a missing line as missing", func(t *testing.T) {
		t.Parallel()
		winA, winB := divergenceWindows("some line", "")
		assert.Contains(t, winA, "some line")
		assert.Equal(t, "(no such line)", winB, "a shorter restatement reads as an absent line, not an empty one")
	})

	t.Run("does not split a multibyte rune", func(t *testing.T) {
		t.Parallel()
		// A window boundary landing mid-rune would print a replacement character, which reads as corruption in the report.
		a := strings.Repeat("日", 80) + "X"
		b := strings.Repeat("日", 80) + "Y"
		winA, winB := divergenceWindows(a, b)
		assert.True(t, utf8.ValidString(winA), "window must stay valid UTF-8")
		assert.True(t, utf8.ValidString(winB))
		assert.Contains(t, winA, "X")
		assert.Contains(t, winB, "Y")
	})
}

// TestFirstDivergence pins the line the report points at.
func TestFirstDivergence(t *testing.T) {
	t.Parallel()

	line, a, b := firstDivergence("one\ntwo\nthree", "one\ntwo\nTHREE")
	assert.Equal(t, 3, line, "1-based, so it matches what a reader counts in the file")
	assert.Equal(t, "three", a)
	assert.Equal(t, "THREE", b)

	line, a, b = firstDivergence("one\ntwo", "one\ntwo\nthree")
	assert.Equal(t, 3, line)
	assert.Empty(t, a, "the shorter side has no line there")
	assert.Equal(t, "three", b)
}
