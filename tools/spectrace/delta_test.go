package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mustParseDeltas parses the in-flight change deltas under changesDir, failing the test on error. Shared by the REMOVED and
// MODIFIED exemption tests, which read two halves of the same single pass.
func mustParseDeltas(t *testing.T, changesDir string) *deltaSections {
	t.Helper()
	d, err := parseDeltaSections(changesDir)
	require.NoError(t, err)
	return d
}

// TestDivergentRestatements covers the check that two in-flight changes cannot restate one requirement with different scenario
// lists.
//
// This is not a style rule. `openspec archive` replaces a requirement's canonical scenario list with the restatement and applies
// changes in sequence, so the last one to archive deletes whatever the others added. Verified against the real CLI while this was
// written: archiving two changes that both restated "Stable counter names" left the canonical requirement missing the first
// change's scenario, with no error and nothing in the output to say so.
func TestDivergentRestatements(t *testing.T) {
	t.Parallel()

	restating := func(scenarios ...string) string {
		var body strings.Builder
		body.WriteString("## MODIFIED Requirements\n\n### Requirement: Stable counter names\nCounters SHALL be stable.\n")
		for _, s := range scenarios {
			body.WriteString("\n#### Scenario: " + s + "\n- **THEN** it holds\n")
		}
		return body.String()
	}

	t.Run("reports what each change would delete", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "adds-retries", "observability-instrumentation", restating("Shared one", "Retries are counted"))
		writeChangeSpec(t, changes, "adds-monitor", "observability-instrumentation", restating("Shared one", "Monitor matches are counted"))

		got := mustParseDeltas(t, changes).divergentRestatements()
		require.Len(t, got, 1)
		require.Equal(t, "observability-instrumentation/stable-counter-names", got[0].requirement)
		require.Equal(t, []string{"adds-monitor", "adds-retries"}, got[0].changes)
		require.Equal(t, []string{"retries-are-counted"}, got[0].missing["adds-monitor"])
		require.Equal(t, []string{"monitor-matches-are-counted"}, got[0].missing["adds-retries"])
	})

	t.Run("agreeing restatements are not a divergence", func(t *testing.T) {
		t.Parallel()
		// Two changes may restate one requirement, and must, once each has listed everything the requirement will end up with.
		// Reporting that would make the check fire on the fixed state as well as the broken one.
		changes := t.TempDir()
		writeChangeSpec(t, changes, "first", "observability-instrumentation", restating("Shared one", "Both list this"))
		writeChangeSpec(t, changes, "second", "observability-instrumentation", restating("Shared one", "Both list this"))

		require.Empty(t, mustParseDeltas(t, changes).divergentRestatements())
	})

	t.Run("a single change restating a requirement is never a divergence", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "only", "observability-instrumentation", restating("Alone"))

		require.Empty(t, mustParseDeltas(t, changes).divergentRestatements())
	})
}
