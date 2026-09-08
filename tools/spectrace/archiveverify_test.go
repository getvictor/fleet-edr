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
		nil,
	))
}

// retiredSet is the requirements some archived change marked REMOVED, with nothing having added them since.
func retiredSet(requirements ...string) map[string]requirementLifecycle {
	out := make(map[string]requirementLifecycle, len(requirements))
	for _, r := range requirements {
		out[r] = requirementLifecycle{retired: "2026-09-07"}
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
		nil,
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
		nil,
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing\n    retired by an archived change and still in the canonical spec")
}

// The change that retires a requirement usually does not also restate it, so a report built only from the restatements would miss
// every one of these. All four on the real tree are that shape.
func TestVerifyArchive_AnUndoneRetirementIsFoundWithoutARestatement(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(nil, canonicalWith("cap/the-thing", "one"), retiredSet("cap/the-thing"), nil)
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
		assert.Contains(t, out, "A line that is NEW is damage this archive did")
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
		text, err := ParseAllRequirementText(specsDir)
		require.NoError(t, err)
		return verifyArchive(restatements, canonicalScenarios(scenarios), retired, text)
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

	// The real shape of the two sides: the change delta is hard-wrapped by hand and the canonical tree is Prettier
	// `proseWrap: never`, so the same requirement text reaches the two parsers looking completely different. If either side
	// normalised differently from the other, every archived requirement would report its whole body as lost.
	t.Run("wrapping alone is not a loss", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-refines-it", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nThe system SHALL do the thing, and it SHALL do\nthe thing in the manner described\nhere."+
			"\n\n#### Scenario: One\n\n- **THEN** it does\n")
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\n"+
			"The system SHALL do the thing, and it SHALL do the thing in the manner described here.\n\n"+
			"#### Scenario: One\n\n- **THEN** it does\n")
		assert.Empty(t, verify(t, changes, specs))
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
		}, "")
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
				}, "")
				assert.Equal(t, []string{"shared"}, got.scenarios)
				assert.Len(t, got.changes, 2, "both changes in the batch are named, since either could have won")
			})
		}
	})

	// The batch a folder belongs to is its first ten characters, including for the malformed double-date folders that predate this.
	for _, tc := range []struct{ name, folder, want string }{
		{"an ordinary archive folder", "2026-06-09-some-change", "2026-06-09"},
		{"a malformed double-date folder", "2026-06-09-2026-06-09-dns-proxy-on-by-default", "2026-06-09"},
		{"a folder too short to carry a date", "short", "short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, archiveDate(tc.folder))
		})
	}
}

// TestVerifyArchive_ARetirementALaterChangeUndidIsNotAFinding covers what a flat "was it ever retired" set could not answer: a
// retirement is not the last word, and a later archived change may legitimately add the requirement back.
//
// A retirement and an addition stamped the SAME date ARE reported, which is the one place this file does not treat a same-batch
// question as unanswerable. Every change in the current release carries one date, so that pair archived remove-then-add is exactly
// the outcome to catch; a historical one appears in the before report too and costs the reader nothing.
func TestVerifyArchive_ARetirementALaterChangeUndidIsNotAFinding(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		life     requirementLifecycle
		findings int
	}{
		{"retired, never added back", requirementLifecycle{retired: "2026-06-02"}, 1},
		{"added back in a later batch", requirementLifecycle{retired: "2026-06-02", added: "2026-06-09"}, 0},
		{"added and retired in one batch", requirementLifecycle{retired: "2026-06-02", added: "2026-06-02"}, 1},
		{"added before it was retired", requirementLifecycle{retired: "2026-06-09", added: "2026-06-02"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, verifyArchive(nil, canonicalWith("cap/the-thing", "one"),
				map[string]requirementLifecycle{"cap/the-thing": tc.life}, nil), tc.findings)
		})
	}
}

// TestArchiveCommands_RefuseAChangesDirThatIsNotThere pins what a typo does. Both walkers treat a missing tree as an empty one,
// which is right for them and would make a mistyped --changes-dir print a clean report with the safeguard switched off, twice, on
// either side of the release checklist's comparison.
func TestArchiveCommands_RefuseAChangesDirThatIsNotThere(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "not-there")
	notADir := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))

	// --specs-dir as well as --changes-dir. A specs path that is not a directory yields an EMPTY canonical set rather than an
	// error, and an empty one classifies every pending ADDED as creating a new requirement, so a pair with no safe order gets
	// printed as a safe one.
	for _, tc := range []struct{ name, flag, dir string }{
		{"a changes path that does not exist", "--changes-dir", missing},
		{"a changes path that is a file", "--changes-dir", notADir},
		{"a specs path that does not exist", "--specs-dir", missing},
		{"a specs path that is a file", "--specs-dir", notADir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, 2, runArchiveVerify([]string{tc.flag, tc.dir}))
			assert.Equal(t, 2, runArchiveOrder([]string{tc.flag, tc.dir}))
		})
	}
}

// TestVerifyArchive_ACanonicalScenarioNoRestatementKeptIsAFinding covers the comparison in the other direction. A restatement
// replaces a requirement WHOLE, so a scenario it does not list is one it retires; archiving a MODIFIED before the ADDED it refines
// re-applies the original body last, and then every scenario the restatement KEPT is present and only the dropped ones show it.
func TestVerifyArchive_ACanonicalScenarioNoRestatementKeptIsAFinding(t *testing.T) {
	t.Parallel()

	// The restatement kept only "kept"; canonical still carries the "dropped" the original ADDED introduced.
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-02-refines-it", scenarios: []string{"kept"}}},
		},
		canonicalWith("cap/the-thing", "kept", "dropped"),
		nil,
		nil,
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing/dropped")
	assert.Contains(t, findings[0], "in the canonical spec, and retired by 2026-06-02-refines-it")
}

// A scenario ANY restatement in the batch kept could be there because that one won, so the canonical side is checked against the
// batch's union while the restatement side is checked against its intersection. Getting this backwards would report every
// scenario the two changes disagree about, twice, in opposite directions.
func TestVerifyArchive_TheCanonicalSideIsCheckedAgainstTheWholeBatch(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {
				{change: "2026-09-07-aaa", scenarios: []string{"shared", "only-aaa"}},
				{change: "2026-09-07-zzz", scenarios: []string{"shared"}},
			},
		},
		canonicalWith("cap/the-thing", "shared", "only-aaa"),
		nil,
		nil,
	), "aaa may have won, so its scenario being canonical is not a retirement that failed")
}

// TestVerifyArchive_ARequirementAddedBackIsCheckedLikeAnyOther covers the other half of "a retirement is not the last word". A
// requirement retired and then re-added is an ordinary requirement again, so its later restatements are verified like anything
// else; skipping the checks on the mere existence of a retirement left those unverified forever.
func TestVerifyArchive_ARequirementAddedBackIsCheckedLikeAnyOther(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-16-refines-it", scenarios: []string{"kept", "lost"}}},
		},
		canonicalWith("cap/the-thing", "kept"),
		map[string]requirementLifecycle{"cap/the-thing": {retired: "2026-06-02", added: "2026-06-09"}},
		nil,
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing/lost")
}

// TestVerifyArchive_ProseTheRestatementCarriedAndCanonicalLacks covers the loss a scenario heading cannot speak for: a
// restatement refines a requirement's normative wording while listing exactly the scenarios the body it replaces already had, and
// archiving it before the ADDED it refines loses the wording with every heading still in place.
func TestVerifyArchive_ProseTheRestatementCarriedAndCanonicalLacks(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{
				change:    "2026-06-02-refines-it",
				scenarios: []string{"one"},
				text:      requirementText{body: []string{"It SHALL do the thing.", "It SHALL also do the refined thing."}},
			}},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		map[string]requirementText{"cap/the-thing": {body: []string{"It SHALL do the thing."}}},
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "It SHALL also do the refined thing.")
	assert.Contains(t, findings[0], "2026-06-02-refines-it")
}

// Prose is compared in BOTH directions, and this is the one review had to ask for twice. A restatement whose whole change is a
// DELETION carries no line the canonical spec lacks, so the loss direction alone reports nothing when it is archived out of order
// and the deleted clause survives. Measured before adding it: 14 lines across 12 requirements, not the flood I assumed.
func TestVerifyArchive_CanonicalProseNoRestatementCarriedIsAFinding(t *testing.T) {
	t.Parallel()
	assert.Len(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{change: "2026-06-02-refines-it", scenarios: []string{"one"},
				text: requirementText{body: []string{"It SHALL do the thing."}}}},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		map[string]requirementText{"cap/the-thing": {body: []string{"It SHALL do the thing.", "An editor added this by hand."}}},
	), 1, "the clause the restatement dropped is still canonical, so its retirement did not take effect")
}

// TestSplitRequirementText pins the two things this normaliser exists to do, which a plain whitespace trim does not: absorb the
// LINE WRAP, and keep each scenario's text under its own name.
//
// The wrap first. The canonical tree is Prettier `proseWrap: never` and the change deltas are hard-wrapped by hand, so without
// this, comparing bodies reports reflow as loss: measured across the archive before it existed, 17 requirements differing and 9
// of them only by reflow.
func TestSplitRequirementText(t *testing.T) {
	t.Parallel()

	t.Run("a hard-wrapped paragraph equals the same text on one line", func(t *testing.T) {
		t.Parallel()
		wrapped := []string{
			"The system SHALL do the thing, and it SHALL do the thing",
			"in the manner described here.",
		}
		oneLine := []string{"The system SHALL do the thing, and it SHALL do the thing in the manner described here."}
		assert.Equal(t, splitRequirementText(oneLine).body, splitRequirementText(wrapped).body)
	})

	t.Run("a blank line and a list marker each start their own logical line", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"First paragraph.", "Second paragraph.", "- a bullet", "- another bullet"},
			splitRequirementText([]string{"First paragraph.", "", "Second", "paragraph.", "- a bullet", "- another bullet"}).body)
	})

	// NUMBERED items too, which review caught the comment promising and the code not doing. `ui-authentication-session` numbers
	// the two entry points of its login requirement, and without this those items merge into the paragraph above them: the
	// finding stops naming which entry point changed, and a list-versus-prose restructuring can compare equal.
	t.Run("a numbered item starts its own logical line", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"The surface is split in two:", "1. **One** does this.", "2. **Two** does that."},
			splitRequirementText([]string{"The surface is split in two:", "1. **One** does this.", "2. **Two** does that."}).body)
	})

	// A number that is not a list marker stays in the paragraph, so a sentence opening with a year is not split off.
	t.Run("a bare number is not a list marker", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"Body. 2026 was the year. 12.5 percent."},
			splitRequirementText([]string{"Body.", "2026 was the year.", "12.5 percent."}).body)
	})

	// A bullet that gained a clause is its own difference rather than being absorbed into the paragraph around it.
	t.Run("a changed bullet does not swallow its neighbours", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"Body.", "- one", "- two"}, splitRequirementText([]string{"Body.", "- one", "- two"}).body)
		assert.Equal(t, []string{"Body.", "- one", "- two, refined"},
			splitRequirementText([]string{"Body.", "- one", "- two, refined"}).body)
	})

	// A scenario's text goes under the scenario's slug, not into the requirement's own body. A scenario that goes missing is
	// reported once by name, and counting its bullets as body text too turned one lost scenario into seven findings.
	t.Run("scenario text is keyed by the scenario", func(t *testing.T) {
		t.Parallel()
		got := splitRequirementText([]string{
			"### Requirement: The thing", "Body.", "",
			"#### Scenario: One", "- **THEN** it does", "",
			"#### Scenario: Two", "- **THEN** it also does",
		})
		assert.Equal(t, []string{"Body."}, got.body)
		assert.Equal(t, map[string][]string{"one": {"- **THEN** it does"}, "two": {"- **THEN** it also does"}}, got.scenarios)
	})

	// A non-Scenario subheading closes whatever was open without opening a scenario, so its text stays comparable as body while
	// the heading itself, being structure rather than prose, is not compared.
	t.Run("another subheading does not open a scenario", func(t *testing.T) {
		t.Parallel()
		got := splitRequirementText([]string{"Body.", "", "#### Notes", "An aside."})
		assert.Equal(t, []string{"Body.", "An aside."}, got.body)
		assert.Empty(t, got.scenarios)
	})
}

// TestVerifyArchive_ScenarioBodyIsComparedUnderItsName covers the gap review found in excluding scenario text: a MODIFIED delta
// that only changes a THEN clause, archived before its ADDED, has that change reverted while the scenario NAME and the
// requirement's own prose both survive, so nothing else in the report notices.
func TestVerifyArchive_ScenarioBodyIsComparedUnderItsName(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{
				change:    "2026-06-02-refines-it",
				scenarios: []string{"one"},
				text:      requirementText{scenarios: map[string][]string{"one": {"- **THEN** it does the refined thing"}}},
			}},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		map[string]requirementText{"cap/the-thing": {scenarios: map[string][]string{"one": {"- **THEN** it does the old thing"}}}},
	)
	// Both directions fire: the refined clause is missing, and the old one it replaced is still there.
	require.Len(t, findings, 2)
	assert.Contains(t, findings[0], "cap/the-thing/one")
	assert.Contains(t, findings[1], "cap/the-thing/one")
}

// A scenario the canonical spec has and the restatement did not mention at all is reported once, by name, and its body is left
// alone. Comparing the body too turned one lost scenario into seven findings.
func TestVerifyArchive_AMissingScenarioIsNotAlsoReportedLineByLine(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{
				change:    "2026-06-02-refines-it",
				scenarios: []string{"kept"},
				text:      requirementText{scenarios: map[string][]string{"kept": {"- **THEN** it does"}}},
			}},
		},
		canonicalWith("cap/the-thing", "kept", "dropped"),
		nil,
		map[string]requirementText{"cap/the-thing": {scenarios: map[string][]string{
			"kept":    {"- **THEN** it does"},
			"dropped": {"- **GIVEN** something", "- **THEN** something else"},
		}}},
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "cap/the-thing/dropped")
	assert.Contains(t, findings[0], "retired by 2026-06-02-refines-it")
}

// TestLastBatchRestatement_ARepeatedLineStillCounts covers the counting bug review found: the shared count is per RESTATEMENT,
// not per occurrence, so a restatement that repeats an identical bullet does not push its own count past the batch size and drop
// the line out of the intersection.
func TestLastBatchRestatement_ARepeatedLineStillCounts(t *testing.T) {
	t.Parallel()
	got := lastBatchRestatement([]archivedRestatement{
		{change: "2026-09-07-aaa", text: requirementText{body: []string{"- the same bullet", "- the same bullet"}}},
		{change: "2026-09-07-zzz", text: requirementText{body: []string{"- the same bullet"}}},
	}, "")
	assert.Equal(t, []string{"- the same bullet"}, got.kept.body,
		"both restatements carried it, so losing every copy has to be reportable")
}

// TestVerifyArchive_ReorderedStepsAreAFinding covers what a set comparison cannot see: a restatement whose only change is the
// ORDER of a scenario's steps is a real refinement, and an out-of-order archive restores the old sequence with every line still
// present.
func TestVerifyArchive_ReorderedStepsAreAFinding(t *testing.T) {
	t.Parallel()
	refined := []string{"- **GIVEN** a thing", "- **WHEN** it happens", "- **THEN** it does"}
	old := []string{"- **WHEN** it happens", "- **GIVEN** a thing", "- **THEN** it does"}

	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{
				change:    "2026-06-02-refines-it",
				scenarios: []string{"one"},
				text:      requirementText{scenarios: map[string][]string{"one": refined}},
			}},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		map[string]requirementText{"cap/the-thing": {scenarios: map[string][]string{"one": old}}},
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "ordered differently by 2026-06-02-refines-it")
}

// The sequence check speaks only for a batch of ONE. Where two restatements are in the batch, which the archive applied is
// exactly what is not recoverable, so neither of their orders is "the" order: taking the first anyway reported six spans as
// reordered on the real tree, every one of them a multi-change batch.
func TestVerifyArchive_OrderIsNotClaimedForABatchOfTwo(t *testing.T) {
	t.Parallel()
	one := []string{"- **GIVEN** a thing", "- **THEN** it does"}
	other := []string{"- **THEN** it does", "- **GIVEN** a thing"}

	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {
				{change: "2026-09-07-aaa", scenarios: []string{"one"},
					text: requirementText{scenarios: map[string][]string{"one": one}}},
				{change: "2026-09-07-zzz", scenarios: []string{"one"},
					text: requirementText{scenarios: map[string][]string{"one": other}}},
			},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		// Canonical matches the FIRST restatement's order and not the second's, so a check that picked either one of them would
		// fire. The set is the same in all three, so nothing else in the report speaks for this span.
		map[string]requirementText{"cap/the-thing": {scenarios: map[string][]string{"one": one}}},
	))
}

// TestLastBatchRestatement_IgnoresAPreviousLifetime covers the case review found last: a requirement retired and later re-added
// has a new body, and restatements from before the re-add describe the old one. Comparing those against the new canonical text
// reports a correct re-add as archive damage.
//
// Same-date restatements are kept, so the batch that did the re-adding is still checked.
func TestLastBatchRestatement_IgnoresAPreviousLifetime(t *testing.T) {
	t.Parallel()
	entries := []archivedRestatement{
		{change: "2026-06-02-first-lifetime", scenarios: []string{"old"}},
		{change: "2026-06-16-after-the-re-add", scenarios: []string{"new"}},
	}
	assert.Equal(t, []string{"new"}, lastBatchRestatement(entries, "2026-06-09").scenarios,
		"the restatement from before the re-add describes a requirement that no longer exists")
	assert.Equal(t, []string{"old"}, lastBatchRestatement(entries[:1], "2026-06-02").scenarios,
		"a restatement in the same batch as the addition is still the current lifetime")
	assert.Empty(t, lastBatchRestatement(entries[:1], "2026-06-09").scenarios,
		"nothing from the current lifetime means nothing to claim, not a claim of nothing")
}

// TestVerifyArchive_AScenarioWhoseBodiesShareNothingIsStillChecked covers the gap review found in iterating the surviving text
// keys rather than the agreed scenario names: two restatements can list the same scenario and share no body line, which leaves
// the intersection with no key for it, and the canonical side of that scenario then goes unchecked even though a canonical line
// neither of them carried is an unambiguous failed retirement.
func TestVerifyArchive_AScenarioWhoseBodiesShareNothingIsStillChecked(t *testing.T) {
	t.Parallel()
	findings := verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {
				{change: "2026-09-07-aaa", scenarios: []string{"one"},
					text: requirementText{scenarios: map[string][]string{"one": {"- **THEN** aaa says this"}}}},
				{change: "2026-09-07-zzz", scenarios: []string{"one"},
					text: requirementText{scenarios: map[string][]string{"one": {"- **THEN** zzz says that"}}}},
			},
		},
		canonicalWith("cap/the-thing", "one"),
		nil,
		map[string]requirementText{"cap/the-thing": {scenarios: map[string][]string{
			"one": {"- **THEN** aaa says this", "- **THEN** neither of them carried this"},
		}}},
	)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "neither of them carried this")
}

// TestVerifyArchive_ARequirementReAddedWithNoLaterRestatementIsLeftAlone covers what testing the entry list before the lifetime
// filter missed: a requirement re-added with no restatement since has restatements only from its PREVIOUS lifetime, the filter
// empties the list, and an empty winner then reports every scenario and every line of its valid new body as retired.
func TestVerifyArchive_ARequirementReAddedWithNoLaterRestatementIsLeftAlone(t *testing.T) {
	t.Parallel()
	assert.Empty(t, verifyArchive(
		map[string][]archivedRestatement{
			"cap/the-thing": {{
				change:    "2026-06-02-first-lifetime",
				scenarios: []string{"an-old-scenario"},
				text:      requirementText{body: []string{"The old body."}},
			}},
		},
		canonicalWith("cap/the-thing", "a-new-scenario"),
		map[string]requirementLifecycle{"cap/the-thing": {retired: "2026-06-09", added: "2026-06-16"}},
		map[string]requirementText{"cap/the-thing": {body: []string{"The new body."}}},
	), "nothing from the current lifetime is no claim to check against, not a claim that everything is missing")
}

// TestArchiveVerify_AnAddedOnlyRequirementIsChecked is issue #909.
//
// Until this, collectArchivedRestatements read `## MODIFIED Requirements` only, so a requirement that was ADDED and never restated
// had no claim against it at all: the archive could drop one of its scenarios, or the last line of the last requirement in a file,
// and nothing here would say so. Most requirements are introduced once and never restated, so the blind spot covered the majority
// of the tree, and it is how the two bullets #901 found reached a release.
//
// Measured on the real tree when the fix landed: findings went from 85 to 215, and the first one inspected was a genuine loss the
// tool had already half-reported. `2026-06-02-add-application-control` ADDED "Set application control command" and the canonical
// spec never gained it; the retirement of the requirement it replaced WAS reported, because that came through a REMOVED, while the
// replacement was invisible.
func TestArchiveVerify_AnAddedOnlyRequirementIsChecked(t *testing.T) {
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
		text, err := ParseAllRequirementText(specsDir)
		require.NoError(t, err)
		return verifyArchive(restatements, canonicalScenarios(scenarios), retired, text)
	}

	t.Run("a scenario the ADDED introduced and the tree lacks is a finding", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-introduces-it", "cap", "# T\n\n## ADDED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: Kept\n\n- **THEN** it does\n\n"+
			"#### Scenario: Lost\n\n- **THEN** it does\n")
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n"+
			"#### Scenario: Kept\n\n- **THEN** it does\n")

		findings := verify(t, changes, specs)
		require.Len(t, findings, 1, "the ADDED is a claim about what the tree should hold, exactly as a MODIFIED is")
		assert.Contains(t, findings[0], "cap/the-thing/lost")
	})

	t.Run("an ADDED the tree carries in full is not a finding", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-introduces-it", "cap", added("The thing"))
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL do the thing.\n\n"+
			"#### Scenario: One\n\n- **THEN** it does\n")
		assert.Empty(t, verify(t, changes, specs), "widening the check must not report a requirement that arrived intact")
	})

	t.Run("a later MODIFIED is the authority over the ADDED it refines", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-introduces-it", "cap", "# T\n\n## ADDED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: One\n\n- **THEN** it does\n\n"+
			"#### Scenario: Retired later\n\n- **THEN** it does\n")
		archived(t, changes, "2026-06-09-refines-it", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: One\n\n- **THEN** it does\n")
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n"+
			"#### Scenario: One\n\n- **THEN** it does\n")
		assert.Empty(t, verify(t, changes, specs),
			"a scenario the ADDED listed and a LATER restatement dropped is a retirement, not a loss")
	})

	t.Run("an ADDED and a MODIFIED in one batch claim only what both list", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		// Same date, so the batch's internal order is unrecoverable and the two are intersected. The MODIFIED refines the
		// requirement with a scenario the ADDED never had; claiming it would report a correct archive as damage.
		archived(t, changes, "2026-06-02-introduces-it", "cap", "# T\n\n## ADDED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: Shared\n\n- **THEN** it does\n")
		archived(t, changes, "2026-06-02-refines-it", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
			"### Requirement: The thing\n\nSHALL.\n\n#### Scenario: Shared\n\n- **THEN** it does\n\n"+
			"#### Scenario: Only the refinement\n\n- **THEN** it does\n")
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n\n### Requirement: The thing\n\nSHALL.\n\n"+
			"#### Scenario: Shared\n\n- **THEN** it does\n")
		assert.Empty(t, verify(t, changes, specs),
			"intersecting under-claims rather than over-claims, which is the direction this command errs in")
	})

	t.Run("an ADDED requirement a later change retired is not a loss", func(t *testing.T) {
		t.Parallel()
		changes, specs := newTree(t)
		archived(t, changes, "2026-06-02-introduces-it", "cap", added("The thing"))
		archived(t, changes, "2026-06-09-retires-it", "cap", removedDelta("The thing"))
		writeCanonical(t, specs, "cap", "# cap\n\n## Requirements\n")
		assert.Empty(t, verify(t, changes, specs))
	})
}

// TestCollectChange_FilesTheLastAddedRequirementUnderAdded pins the routing, which is the part of #909 that is easy to get wrong.
//
// A requirement is recorded when the scanner LEAVES it, at the next `## ` heading or at end of file, by which point the section
// being scanned has already moved on. Routing on the live section rather than on the one the requirement was declared under files
// the last requirement of an ADDED block under whatever follows it, and a delta that ends with ADDED loses it entirely.
func TestCollectChange_FilesTheLastAddedRequirementUnderAdded(t *testing.T) {
	t.Parallel()

	changes := t.TempDir()
	writeChange(t, changes, "a-change", "cap", "# T\n\n## MODIFIED Requirements\n\n"+
		"### Requirement: Refined\n\nSHALL.\n\n#### Scenario: M\n\n- **THEN** it does\n\n"+
		"## ADDED Requirements\n\n"+
		"### Requirement: Introduced\n\nSHALL.\n\n#### Scenario: A\n\n- **THEN** it does\n")

	d := &deltaSections{
		removedRequirements:  make(map[string]struct{}),
		addedBy:              make(map[string]map[string]struct{}),
		removedBy:            make(map[string]map[string]struct{}),
		modifiedRestatements: make(map[string]map[string]restatement),
		addedStatements:      make(map[string]map[string]restatement),
	}
	require.NoError(t, d.collectChange(filepath.Join(changes, "a-change")))

	assert.Contains(t, d.addedStatements, "cap/introduced", "the ADDED block is last, so it is flushed at end of file")
	assert.NotContains(t, d.modifiedRestatements, "cap/introduced", "and must not be filed as a restatement of itself")
	assert.Contains(t, d.modifiedRestatements, "cap/refined")
	assert.NotContains(t, d.addedStatements, "cap/refined")
}

// TestVerifyArchive_AnAddedDoesNotExcuseAModifiedsRetirement is the regression review caught in the #909 fold, and it is the case
// that shows the two directions of this check cannot read the same entries.
//
// The claim set and the EXCUSE set pull opposite ways. Widening what the batch claims can only miss a finding: the loss direction
// intersects, so an extra entry claims less. Widening what the batch EXCUSES makes the canonical-side checks weaker, because they
// read everListed as "some delta here kept this, so its presence is not an unapplied retirement". Folding ADDED entries into both
// silenced a finding the MODIFIED-only input reported, which is exactly the out-of-order damage this command exists to catch.
//
// A MODIFIED replaces the requirement whole and is sequenced after the ADDED it refines, so what the MODIFIED omits is retired
// even when the ADDED listed it.
func TestVerifyArchive_AnAddedDoesNotExcuseAModifiedsRetirement(t *testing.T) {
	t.Parallel()

	sameBatch := map[string][]archivedRestatement{
		"cap/the-thing": {
			{change: "2026-06-02-introduces-it", added: true, scenarios: []string{"shared", "retired"}},
			{change: "2026-06-02-refines-it", scenarios: []string{"shared"}},
		},
	}
	findings := verifyArchive(sameBatch, canonicalWith("cap/the-thing", "shared", "retired"), nil, nil)
	require.Len(t, findings, 1, "the MODIFIED retired it, so the canonical copy is a retirement the archive did not apply")
	assert.Contains(t, findings[0], "cap/the-thing/retired")

	// A batch of ADDED entries alone IS its own authority: there is no restatement to say otherwise, and this is the shape #909
	// added. Here the scenario is genuinely part of the requirement, so its presence is not damage.
	addedOnly := map[string][]archivedRestatement{
		"cap/the-thing": {{change: "2026-06-02-introduces-it", added: true, scenarios: []string{"shared", "kept"}}},
	}
	assert.Empty(t, verifyArchive(addedOnly, canonicalWith("cap/the-thing", "shared", "kept"), nil, nil),
		"an ADDED-only batch excuses what it listed, or every requirement introduced once would report its own scenarios")
}
