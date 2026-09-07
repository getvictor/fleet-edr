package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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

// retiredSet is the requirements some archived change marked REMOVED.
func retiredSet(requirements ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(requirements))
	for _, r := range requirements {
		out[r] = struct{}{}
	}
	return out
}

// A requirement a change retired legitimately has nothing canonical left, and reporting every one of its scenarios as lost would
// bury a real finding under every retirement the project has ever made.
//
// The pair is the real one that made this matter: `latch-dns-proxy-bypass` restates a requirement and `dns-proxy-no-bypass`
// retires it, both pending, so both archive on the same day. Two earlier versions of this decided by reading the folder names,
// first alphabetically and then by date, and the exemption no longer asks the folders anything: the requirement is gone and a
// retirement is recorded, which settles it whatever the names say.
func TestVerifyArchive_ARetiredRequirementIsNotALoss(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-09-07-latch-dns-proxy-bypass", scenarios: []string{"one"}}},
		},
		map[string]map[string]struct{}{},
		retiredSet("cap/the-thing"),
	))
}

// A retirement that did not take effect is itself the finding, and this is the hole the date comparison left: a later change
// re-created the requirement, or the retirement was never applied, so it is right there in the canonical tree.
//
// Reported instead of, not as well as, its missing scenarios. The requirement should not exist at all, so counting which of its
// scenarios survived is accounting for a thing that has to be resolved first. Four requirements are in this state on the real tree,
// all retired by `2026-06-02-add-application-control` and none of them re-added since.
func TestVerifyArchive_ARetirementTheTreeContradictsIsAFinding(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-09-07-refines-it", scenarios: []string{"kept", "lost"}}},
		},
		canonicalWith("cap/the-thing", "kept"),
		retiredSet("cap/the-thing"),
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing\n    retired by an archived change and still in the canonical spec")
}

// The change that retires a requirement usually does not also restate it, so a report built only from the restatements would miss
// every one of these. All four on the real tree are that shape.
func TestVerifyArchive_AnUndoneRetirementIsFoundWithoutARestatement(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(nil, canonicalWith("cap/the-thing", "one"), retiredSet("cap/the-thing"))
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing")
}

// A requirement that vanished with NOTHING retiring it is the whole requirement lost, and every scenario it listed is reported.
func TestVerifyArchive_AVanishedRequirementWithNoRetirementIsALoss(t *testing.T) {
	t.Parallel()
	assert.Len(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-09-07-refines-it", scenarios: []string{"one", "two"}}},
		},
		map[string]map[string]struct{}{},
		nil,
	), 2)
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

// removed is the minimal `## REMOVED Requirements` delta, which the archive-order helpers do not need and this does.
func removedDelta(name string) string {
	return "# T\n\n## REMOVED Requirements\n\n### Requirement: " + name + "\n\nRetired.\n"
}

// writeCanonical writes one canonical spec file, which is the ground truth the exemption consults.
func writeCanonical(t *testing.T, specsDir, capability, body string) {
	t.Helper()
	dir := filepath.Join(specsDir, capability)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// TestArchiveVerify_OverARealTree exercises the traversal and the spec parse together, because every other test in this file
// hands verifyArchive maps it built itself and so cannot catch the two things that only the filesystem decides: whether the
// archive walk orders folders the way "the last restatement wins" assumes, and whether the two sides derive the same key from a
// requirement title.
func TestArchiveVerify_OverARealTree(t *testing.T) {
	t.Parallel()

	newTree := func(t *testing.T) (string, string) {
		t.Helper()
		changes, specs := t.TempDir(), t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(changes, archiveDirName), 0o750))
		return changes, specs
	}
	archived := func(t *testing.T, changesDir, folder, capability, body string) {
		t.Helper()
		writeChange(t, filepath.Join(changesDir, archiveDirName), folder, capability, body)
	}
	verify := func(t *testing.T, changesDir, specsDir string) []string {
		t.Helper()
		restatements, retired, err := collectArchivedRestatements(changesDir)
		require.NoError(t, err)
		scenarios, err := ParseAllSpecs(specsDir)
		require.NoError(t, err)
		return verifyArchive(restatements, canonicalScenarios(scenarios), retired)
	}

	// The later folder's restatement is the authority, so a scenario only the earlier one listed is a retirement and not a loss.
	// This is the assumption the walk's sort order carries, and nothing but a real tree tests it.
	t.Run("the later folder wins", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-first", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: One\n\n- **THEN** it does\n\n"+
			"#### Scenario: Dropped later\n\n- **THEN** it does\n")
		archived(t, changes, "2026-06-09-second", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: One\n\n- **THEN** it does\n")
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n"+
			"#### Scenario: One\n\n- **THEN** it does\n")
		assert.Empty(t, verify(t, changes, specs))
	})

	// A retirement stamped the SAME DATE as the restatement excuses the absence, and the requirement really is gone from the tree.
	// Two earlier versions of the exemption read the folder names to decide this and each got a different answer.
	t.Run("a same-date retirement excuses an absent requirement", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-09-07-latch-dns-proxy-bypass", "cap", modified("The thing"))
		archived(t, changes, "2026-09-07-dns-proxy-no-bypass", "cap", removedDelta("The thing"))
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n")
		assert.Empty(t, verify(t, changes, specs))
	})

	// The same retirement is a FINDING once the requirement is back in the tree, which is the case the date comparison missed:
	// a later change re-created it, so the retirement the archive recorded never took effect.
	t.Run("a retirement the tree contradicts is itself a finding", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-09-07-latch-dns-proxy-bypass", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: Kept\n\n- **THEN** it does\n\n"+
			"#### Scenario: Lost\n\n- **THEN** it does\n")
		archived(t, changes, "2026-09-07-dns-proxy-no-bypass", "cap", removedDelta("The thing"))
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n"+
			"#### Scenario: Kept\n\n- **THEN** it does\n")
		findings := verify(t, changes, specs)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0], "retired by an archived change and still in the canonical spec")
	})

	// An archive subtree that does not exist is a project that has never released, not an error.
	t.Run("no archive subtree is not an error", func(t *testing.T) {
		t.Parallel()
		restatements, retired, err := collectArchivedRestatements(t.TempDir())
		require.NoError(t, err)
		assert.Empty(t, restatements)
		assert.Empty(t, retired)
	})
}

// TestRunArchiveVerify_ReportsWithoutGating drives the command path itself, since the exit code is what the release checklist and
// any wrapper script read.
func TestRunArchiveVerify_ReportsWithoutGating(t *testing.T) {
	t.Parallel()
	changes, specs := t.TempDir(), t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(changes, archiveDirName), 0o750))
	writeChange(t, filepath.Join(changes, archiveDirName), "2026-06-02-refines-it", "cap", modified("The thing"))
	writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n")

	// A finding is present (the requirement is absent with nothing retiring it) and the command still succeeds.
	assert.Equal(t, 0, runArchiveVerify([]string{"--specs-dir", specs, "--changes-dir", changes}))
	assert.Equal(t, 2, runArchiveVerify([]string{"--specs-dir", filepath.Join(specs, "nope")}))
}

// TestLastBatchRestatement pins what the check compares against when a requirement was restated more than once, which review
// caught it getting wrong: it took the last FOLDER, and folders in one batch share a date and so sort alphabetically.
func TestLastBatchRestatement(t *testing.T) {
	t.Parallel()

	// A later batch replaces an earlier one outright, which is the ordinary case and the one folder order does answer.
	t.Run("a later batch wins", func(t *testing.T) {
		t.Parallel()
		got := lastBatchRestatement([]archivedRestatement{
			{change: "2026-06-02-first", scenarios: []string{"one", "dropped-later"}},
			{change: "2026-06-09-second", scenarios: []string{"one"}},
		})
		assert.Equal(t, []string{"one"}, got.scenarios)
		assert.Equal(t, []string{"2026-06-09-second"}, got.changes)
	})

	// Within ONE batch exactly one restatement wins and the rest are discarded by design, and which one is not recoverable. A
	// scenario every restatement in the batch listed is canonical whichever won; one only some listed is unrecoverable, and
	// unrecoverable is silence here. Eight of the sixty-seven archived requirements have a batch like this, and seven of those
	// eight disagree, so the alphabetical pick was doing real work.
	t.Run("a scenario only one restatement in the batch listed is not claimed", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ name, first, second string }{
			{"the fuller one sorts first", "2026-09-07-aaa", "2026-09-07-zzz"},
			{"the fuller one sorts last", "2026-09-07-zzz", "2026-09-07-aaa"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got := lastBatchRestatement([]archivedRestatement{
					{change: tc.first, scenarios: []string{"shared", "only-here"}},
					{change: tc.second, scenarios: []string{"shared"}},
				})
				assert.Equal(t, []string{"shared"}, got.scenarios)
				assert.Len(t, got.changes, 2, "both changes in the batch are named, since either could have won")
			})
		}
	})

	// The malformed double-date folders that predate this still group by their first ten characters.
	t.Run("a malformed double-date folder still carries its date", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "2026-06-09", archiveDate("2026-06-09-2026-06-09-dns-proxy-on-by-default"))
		assert.Equal(t, "2026-06-09", archiveDate("2026-06-09-some-change"))
		assert.Equal(t, "short", archiveDate("short"))
	})
}
