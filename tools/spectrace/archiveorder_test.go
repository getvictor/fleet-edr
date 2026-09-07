package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeChange writes one in-flight change's delta so a test can state its ADDED / MODIFIED / REMOVED sections directly.
func writeChange(t *testing.T, changesDir, change, capability, body string) {
	t.Helper()
	dir := filepath.Join(changesDir, change, "specs", capability)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// added, modified and removed build the minimal delta shapes. A MODIFIED entry needs a scenario, because the parser deliberately
// drops one that lists none (a delta mid-write), and an entry that never reaches the index cannot constrain anything.
func added(name string) string {
	return "# T\n\n## ADDED Requirements\n\n### Requirement: " + name + "\n\nSHALL do the thing.\n\n#### Scenario: One\n\n- **THEN** it does\n"
}

func modified(name string) string {
	return "# T\n\n## MODIFIED Requirements\n\n### Requirement: " + name + "\n\nSHALL do the thing, refined.\n\n#### Scenario: One\n\n- **THEN** it does\n"
}

func removed(name string) string {
	return "# T\n\n## REMOVED Requirements\n\n### Requirement: " + name + "\n"
}

// TestArchiveConstraints_AddedBeforeModified is the shape issue #901 is about, and the one findRestatementConflicts cannot see:
// it compares MODIFIED against MODIFIED, so an ADDED beside a MODIFIED went unreported while being the commoner case.
func TestArchiveConstraints_AddedBeforeModified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeChange(t, dir, "introduces-it", "cap", added("The thing"))
	writeChange(t, dir, "refines-it", "cap", modified("The thing"))

	sections, err := parseDeltaSections(dir)
	require.NoError(t, err)
	constraints := archiveConstraints(sections)

	require.Len(t, constraints, 1)
	assert.Equal(t, "introduces-it", constraints[0].before)
	assert.Equal(t, "refines-it", constraints[0].after,
		"applied the other way round, the refinement is replaced by the original body and is gone with no error")
	assert.Equal(t, "cap/the-thing", constraints[0].requirement)
}

// A retirement is constrained for a sharper reason than a refinement: applied first, the requirement is deleted and then
// re-created by the other change, so the retirement silently does not happen.
func TestArchiveConstraints_RemovalIsSequencedToo(t *testing.T) {
	t.Parallel()

	t.Run("an ADDED still comes first", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeChange(t, dir, "introduces-it", "cap", added("The thing"))
		writeChange(t, dir, "retires-it", "cap", removed("The thing"))

		sections, err := parseDeltaSections(dir)
		require.NoError(t, err)
		constraints := archiveConstraints(sections)
		require.Len(t, constraints, 1)
		assert.Equal(t, "introduces-it", constraints[0].before)
		assert.Equal(t, "retires-it", constraints[0].after)
	})

	// No ADDED among the pending changes: the requirement is already canonical, so the restatement has to land before the
	// retirement or the retirement is undone by it.
	t.Run("a MODIFIED comes before a REMOVED of an already-canonical requirement", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeChange(t, dir, "refines-it", "cap", modified("The thing"))
		writeChange(t, dir, "retires-it", "cap", removed("The thing"))

		sections, err := parseDeltaSections(dir)
		require.NoError(t, err)
		constraints := archiveConstraints(sections)
		require.Len(t, constraints, 1)
		assert.Equal(t, "refines-it", constraints[0].before)
		assert.Equal(t, "retires-it", constraints[0].after)
	})
}

// Two MODIFIEDs of one requirement are NOT sequenced here, and that is the division of labour rather than an omission:
// findRestatementConflicts requires them to be identical, which makes "the last one wins" harmless between them.
func TestArchiveConstraints_TwoModifiedNeedNoOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeChange(t, dir, "one", "cap", modified("The thing"))
	writeChange(t, dir, "two", "cap", modified("The thing"))

	sections, err := parseDeltaSections(dir)
	require.NoError(t, err)
	assert.Empty(t, archiveConstraints(sections))
}

// One change that both adds and modifies the same requirement has nothing to sequence against itself.
func TestArchiveConstraints_OneChangeIsNotConstrainedAgainstItself(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeChange(t, dir, "does-both", "cap",
		"# T\n\n## ADDED Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n#### Scenario: One\n\n- **THEN** it does\n\n"+
			"## MODIFIED Requirements\n\n### Requirement: The thing\n\nSHALL, refined.\n\n#### Scenario: One\n\n- **THEN** it does\n")

	sections, err := parseDeltaSections(dir)
	require.NoError(t, err)
	assert.Empty(t, archiveConstraints(sections))
}

func TestArchiveOrder_RespectsConstraintsAndIsDeterministic(t *testing.T) {
	t.Parallel()
	changes := []string{"zeta", "alpha", "mid"}
	constraints := []archiveConstraint{
		{before: "zeta", after: "alpha", requirement: "cap/r"},
	}

	order, cycle := archiveOrder(changes, constraints)
	require.Nil(t, cycle)
	assert.Equal(t, []string{"mid", "zeta", "alpha"}, order,
		"alphabetical among the unblocked, so two runs on one tree print the same order")

	// Same inputs in a different order produce the same result, which is what makes this something a checklist can name.
	again, _ := archiveOrder([]string{"mid", "alpha", "zeta"}, constraints)
	assert.Equal(t, order, again)
}

// A cycle is a real conflict no order fixes, and breaking it arbitrarily would hide exactly the loss this exists to prevent.
func TestArchiveOrder_ReportsACycle(t *testing.T) {
	t.Parallel()
	order, cycle := archiveOrder([]string{"a", "b", "c"}, []archiveConstraint{
		{before: "a", after: "b", requirement: "cap/one"},
		{before: "b", after: "a", requirement: "cap/two"},
	})
	assert.Equal(t, []string{"c"}, order, "what can be ordered still is")
	assert.Equal(t, []string{"a", "b"}, cycle)
}

// A constraint naming a change that is not pending is dropped rather than treated as an unsatisfiable prerequisite: it means the
// delta references something already archived, which would otherwise wedge the whole order.
func TestArchiveOrder_IgnoresConstraintsOnChangesThatAreNotPending(t *testing.T) {
	t.Parallel()
	order, cycle := archiveOrder([]string{"here"}, []archiveConstraint{
		{before: "already-archived", after: "here", requirement: "cap/r"},
	})
	require.Nil(t, cycle)
	assert.Equal(t, []string{"here"}, order)
}

func TestPrintArchiveOrder(t *testing.T) {
	t.Parallel()

	t.Run("says so plainly when nothing is constrained", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.True(t, printArchiveOrder(&buf, []string{"a", "b"}, nil))
		assert.Contains(t, buf.String(), "no ordering constraints")
	})

	// The constraints are printed as well as the order because the order alone is not checkable: a reader has no way to tell a
	// real prerequisite from an alphabetical accident, and the point is that they can see why before archiving 88 of them.
	t.Run("prints the reason beside the order", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		ok := printArchiveOrder(&buf, []string{"introduces-it", "refines-it"}, []archiveConstraint{
			{before: "introduces-it", after: "refines-it", requirement: "cap/the-thing"},
		})
		assert.True(t, ok)
		out := buf.String()
		assert.Contains(t, out, "must be archived before refines-it")
		assert.Contains(t, out, "cap/the-thing")
		assert.Less(t, strings.Index(out, "1. introduces-it"), strings.Index(out, "2. refines-it"))
	})

	t.Run("reports a cycle as a failure rather than picking an order", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		ok := printArchiveOrder(&buf, []string{"a", "b"}, []archiveConstraint{
			{before: "a", after: "b", requirement: "cap/one"},
			{before: "b", after: "a", requirement: "cap/two"},
		})
		assert.False(t, ok, "no order satisfies it, so the caller must not be told one does")
		assert.Contains(t, buf.String(), "No order satisfies all of them")
	})
}
