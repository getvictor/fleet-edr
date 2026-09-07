package main

import (
	"bytes"
	"errors"
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
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// added, modified and removed build the minimal delta shapes. A MODIFIED entry needs a scenario, because the parser deliberately
// drops one that lists none (a delta mid-write), and an entry that never reaches the index cannot constrain anything.
func added(name string) string {
	return "# T\n\n## ADDED Requirements\n\n### Requirement: " + name + "\n\nSHALL do the thing.\n\n#### Scenario: One\n\n- **THEN** it does\n"
}

func modified(name string) string {
	return "# T\n\n## MODIFIED Requirements\n\n### Requirement: " + name +
		"\n\nSHALL do the thing, refined.\n\n#### Scenario: One\n\n- **THEN** it does\n"
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
	constraints := archiveConstraints(sections, nil)

	require.Len(t, constraints, 1)
	assert.Equal(t, "introduces-it", constraints[0].before)
	assert.Equal(t, "refines-it", constraints[0].after,
		"applied the other way round, the refinement is replaced by the original body and is gone with no error")
	assert.Equal(t, "cap/the-thing", constraints[0].requirement)
}

// A retirement is constrained for a sharper reason than a refinement: applied first, the requirement is deleted and then
// re-created by the other change, so the retirement silently does not happen. Either kind of predecessor pins it.
func TestArchiveConstraints_RemovalIsSequencedToo(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		other string
		delta string
		why   string
	}{
		{"an ADDED comes first", "introduces-it", added("The thing"),
			"the requirement has to exist before it can be retired"},
		{"a MODIFIED comes first", "refines-it", modified("The thing"),
			"the restatement re-creates the requirement, so a retirement before it is undone by it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeChange(t, dir, tc.other, "cap", tc.delta)
			writeChange(t, dir, "retires-it", "cap", removed("The thing"))

			sections, err := parseDeltaSections(dir)
			require.NoError(t, err)
			constraints := archiveConstraints(sections, nil)
			require.Len(t, constraints, 1)
			assert.Equal(t, tc.other, constraints[0].before, tc.why)
			assert.Equal(t, "retires-it", constraints[0].after)
		})
	}
}

// The three-way case, and the one review found: an ADDED, a REMOVED and a MODIFIED of one requirement in three separate changes.
// The retirement still has to come after the restatement, and the presence of an adder does not change that. Skipping the
// modifier-before-remover edge whenever any adder existed made add-remove-modify a legal order, which recreates the requirement
// after retiring it, which is the exact loss this tool exists to prevent.
func TestArchiveConstraints_AddRemoveAndModifyAreAllSequenced(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeChange(t, dir, "introduces-it", "cap", added("The thing"))
	writeChange(t, dir, "refines-it", "cap", modified("The thing"))
	writeChange(t, dir, "retires-it", "cap", removed("The thing"))

	sections, err := parseDeltaSections(dir)
	require.NoError(t, err)
	constraints := archiveConstraints(sections, nil)

	pairs := make(map[string]bool, len(constraints))
	for _, c := range constraints {
		pairs[c.before+" -> "+c.after] = true
	}
	assert.True(t, pairs["introduces-it -> refines-it"], "the requirement must exist before it is refined")
	assert.True(t, pairs["introduces-it -> retires-it"], "and before it is retired")
	assert.True(t, pairs["refines-it -> retires-it"],
		"and the retirement must come last, or the restatement recreates what the retirement removed")

	order, cycle := archiveOrder([]string{"introduces-it", "refines-it", "retires-it"}, constraints)
	require.Nil(t, cycle)
	assert.Equal(t, []string{"introduces-it", "refines-it", "retires-it"}, order)
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
	assert.Empty(t, archiveConstraints(sections, nil))
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
	assert.Empty(t, archiveConstraints(sections, nil))
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

// A change that merely DEPENDS on a cycle is stuck too, and naming it sends someone to reconcile a delta that is not the problem.
func TestArchiveOrder_BlamesOnlyTheCycle(t *testing.T) {
	t.Parallel()
	// a and b are the cycle; c depends on a and is blameless; d is free.
	order, cycle := archiveOrder([]string{"a", "b", "c", "d"}, []archiveConstraint{
		{before: "a", after: "b", requirement: "cap/one"},
		{before: "b", after: "a", requirement: "cap/two"},
		{before: "a", after: "c", requirement: "cap/three"},
	})
	assert.Equal(t, []string{"d"}, order)
	assert.Equal(t, []string{"a", "b"}, cycle, "c is stuck behind the cycle but is not part of it")
}

// Two cycles joined by a path, which is the counterexample review gave and which the previous sink-peel implementation got
// wrong: the joining node has a prerequisite and a dependent, so it survived the peel, while being on no cycle at all. Having an
// edge in each direction is not the same as being able to get back to yourself.
func TestArchiveOrder_DoesNotBlameANodeBetweenTwoCycles(t *testing.T) {
	t.Parallel()
	// a<->b and d<->e, joined by b -> c -> d. Only the four cycle members are at fault; c and the free change are not.
	order, cycle := archiveOrder([]string{"a", "b", "c", "d", "e", "free"}, []archiveConstraint{
		{before: "a", after: "b", requirement: "cap/1"},
		{before: "b", after: "a", requirement: "cap/2"},
		{before: "b", after: "c", requirement: "cap/3"},
		{before: "c", after: "d", requirement: "cap/4"},
		{before: "d", after: "e", requirement: "cap/5"},
		{before: "e", after: "d", requirement: "cap/6"},
	})
	assert.Equal(t, []string{"free"}, order)
	assert.Equal(t, []string{"a", "b", "d", "e"}, cycle,
		"c joins the two cycles and is stuck behind one, but reconciling c would not break either")
}

// stubbornWriter fails after n successful writes, which is what a broken pipe partway through the plan looks like.
type stubbornWriter struct {
	ok  int
	err error
}

func (w *stubbornWriter) Write(p []byte) (int, error) {
	if w.ok == 0 {
		return 0, w.err
	}
	w.ok--
	return len(p), nil
}

func TestPrintArchiveOrder(t *testing.T) {
	t.Parallel()

	// The list is printed even with nothing to sequence, because the checklist directs the operator to archive in the order this
	// prints and there is no other listing step left to fall back on.
	t.Run("still prints the list when nothing is constrained", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 0, printArchiveOrder(&buf, []string{"b", "a"}, nil))
		out := buf.String()
		assert.Contains(t, out, "no ordering constraints")
		assert.Contains(t, out, "1. a")
		assert.Contains(t, out, "2. b")
	})

	// A plan truncated by a broken pipe, reported as success, is the one way this tool could cause the loss it exists to prevent.
	// It exits 2 rather than the 1 a cycle uses, because the usage text and the checklist both define 1 as "reconcile a cycle" and
	// a full disk reading as one sends the release engineer looking for a cycle that is not there.
	t.Run("a truncated plan fails, and not as a cycle", func(t *testing.T) {
		t.Parallel()
		w := &stubbornWriter{ok: 1, err: errors.New("pipe closed")}
		assert.Equal(t, 2, printArchiveOrder(w, []string{"a", "b"}, []archiveConstraint{
			{before: "a", after: "b", requirement: "cap/r"},
		}))
	})

	// A cycle report that a broken pipe truncated is still a write failure, not a cycle verdict the caller can act on.
	t.Run("a truncated cycle report fails as a write, not as a cycle", func(t *testing.T) {
		t.Parallel()
		w := &stubbornWriter{err: errors.New("pipe closed")}
		assert.Equal(t, 2, printArchiveOrder(w, []string{"a", "b"}, []archiveConstraint{
			{before: "a", after: "b", requirement: "cap/one"},
			{before: "b", after: "a", requirement: "cap/two"},
		}))
	})

	// The constraints are printed as well as the order because the order alone is not checkable: a reader has no way to tell a
	// real prerequisite from an alphabetical accident, and the point is that they can see why before archiving 88 of them.
	t.Run("prints the reason beside the order", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 0, printArchiveOrder(&buf, []string{"introduces-it", "refines-it"}, []archiveConstraint{
			{before: "introduces-it", after: "refines-it", requirement: "cap/the-thing"},
		}))
		out := buf.String()
		assert.Contains(t, out, "must be archived before refines-it")
		assert.Contains(t, out, "cap/the-thing")
		assert.Less(t, strings.Index(out, "1. introduces-it"), strings.Index(out, "2. refines-it"))
	})

	t.Run("reports a cycle as a failure rather than picking an order", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 1, printArchiveOrder(&buf, []string{"a", "b"}, []archiveConstraint{
			{before: "a", after: "b", requirement: "cap/one"},
			{before: "b", after: "a", requirement: "cap/two"},
		}), "no order satisfies it, so the caller must not be told one does")
		assert.Contains(t, buf.String(), "No order satisfies all of them")
	})
}

// TestArchiveConstraints_AddingWhatAlreadyExistsIsNotOrderable pins the pair review raised. One author retiring a requirement
// while another re-introduces it wants remove-then-add; the ordinary create-then-retire wants add-then-remove; the two are the
// same two files, and only the canonical tree separates them.
//
// A pending ADDED for a requirement that already exists is malformed rather than ambiguous, so the pair is surfaced through the
// cycle path instead of being resolved by a guess that leaves one of the two authors with something their delta did not say.
func TestArchiveConstraints_AddingWhatAlreadyExistsIsNotOrderable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeChange(t, dir, "reintroduces-it", "cap", added("The thing"))
	writeChange(t, dir, "retires-it", "cap", removed("The thing"))
	sections, err := parseDeltaSections(dir)
	require.NoError(t, err)

	// Absent from the canonical tree, this is an ordinary create-then-retire and orders cleanly.
	order, cycle := archiveOrder([]string{"reintroduces-it", "retires-it"}, archiveConstraints(sections, nil))
	require.Nil(t, cycle)
	assert.Equal(t, []string{"reintroduces-it", "retires-it"}, order)

	// Present in it, nothing here says which the authors meant, and the pair is reported rather than ordered.
	existing := map[string]struct{}{"cap/the-thing": {}}
	_, cycle = archiveOrder([]string{"reintroduces-it", "retires-it"}, archiveConstraints(sections, existing))
	assert.Equal(t, []string{"reintroduces-it", "retires-it"}, cycle)
}
