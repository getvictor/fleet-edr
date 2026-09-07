package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeInFlightDelta writes one in-flight change delta and returns the path it wrote.
func writeInFlightDelta(t *testing.T, changesDir, change, capability, body string) string {
	t.Helper()
	dir := filepath.Join(changesDir, change, "specs", capability)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	path := filepath.Join(dir, "spec.md")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// normativeDelta is a delta whose requirement is normative, so its scenarios are gated rather than advisory.
func normativeDelta(requirement, scenario string) string {
	return strings.Join([]string{
		"# Cap", "", "## ADDED Requirements", "",
		"### Requirement: " + requirement, "",
		"The system SHALL do the thing.", "",
		"#### Scenario: " + scenario, "",
		"- WHEN x THEN y", "",
	}, "\n")
}

// TestInFlightScenarios covers what the gate reads, which is more than parseChangeScenarioIDs collects.
//
// The archive exclusion is asserted rather than assumed: an archived change's delta has already been merged into the canonical
// tree, so gating its scenarios again would report every archived scenario against whoever next touches that directory.
func TestInFlightScenarios(t *testing.T) {
	t.Parallel()
	changes := t.TempDir()
	writeInFlightDelta(t, changes, "live-change", "cap-a", normativeDelta("A req", "A scenario"))
	writeInFlightDelta(t, changes, filepath.Join(archiveDirName, "2026-01-01-old"), "cap-b",
		normativeDelta("Old req", "Old scenario"))

	got, err := InFlightScenarios(changes)
	require.NoError(t, err)

	ids := make([]string, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []string{"cap-a/a-req/a-scenario"}, ids, "the archive is already canonical and must not be gated twice")
	require.Len(t, got, 1)
	assert.True(t, got[0].Normative, "the requirement says SHALL, so its scenarios are gated rather than advisory")
	assert.Positive(t, got[0].SourceLine, "a reader has to be told where to add the marker")
}

// TestInFlightScenarios_NoChangesDir pins the empty case, since a repository with no in-flight proposals must behave exactly
// as it did before this gate existed rather than erroring.
func TestInFlightScenarios_NoChangesDir(t *testing.T) {
	t.Parallel()
	got, err := InFlightScenarios(filepath.Join(t.TempDir(), "absent"))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestUngatedInFlight_E2E is the gate itself, against a real git repository, because the property that makes it usable is the
// SCOPING and scoping is a git question.
//
// In-flight holds every change merged since the last release, and the archive is batched at release time, so most of what is in
// that directory on any given day was written by somebody else. A gate over all of it would fail every pull request in the
// repository. The one this branch adds is the one the project rule is about.
func TestUngatedInFlight_E2E(t *testing.T) { //nolint:paralleltest // uses t.Chdir; cannot run in parallel
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "--quiet")
	runGit(t, dir, "config", "user.email", "spectrace@example.test")
	runGit(t, dir, "config", "user.name", "spectrace test")

	changes := filepath.Join(dir, "openspec", "changes")
	// Somebody else's change, already merged and awaiting the release archive. It is deliberately unmarked.
	writeInFlightDelta(t, changes, "someone-elses", "cap-other", normativeDelta("Their req", "Their scenario"))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "--quiet", "-m", "baseline")
	runGit(t, dir, "branch", "base")

	// This branch adds one normative scenario and one advisory one.
	writeInFlightDelta(t, changes, "mine", "cap-mine", normativeDelta("My req", "My scenario"))
	writeInFlightDelta(t, changes, "mine-advisory", "cap-advisory", strings.Join([]string{
		"# Cap", "", "## ADDED Requirements", "",
		"### Requirement: An advisory req", "",
		"This requirement describes something without requiring it.", "",
		"#### Scenario: An advisory scenario", "",
		"- WHEN x THEN y", "",
	}, "\n"))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "--quiet", "-m", "mine")
	t.Chdir(dir)

	t.Run("gates what this branch added, and only that", func(t *testing.T) {
		got, err := UngatedInFlight(context.Background(), "openspec/changes", "base", nil, nil)
		require.NoError(t, err)

		ids := make([]string, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
		}
		assert.Equal(t, []string{"cap-mine/my-req/my-scenario"}, ids)
		assert.NotContains(t, ids, "cap-other/their-req/their-scenario",
			"somebody else's unmarked scenario must not fail this branch, or the gate wedges the whole repository")
		assert.NotContains(t, ids, "cap-advisory/an-advisory-req/an-advisory-scenario",
			"an advisory requirement is not gated in the canonical tree either")
	})

	t.Run("a marker satisfies it", func(t *testing.T) {
		covered := map[string][]Marker{"cap-mine/my-req/my-scenario": {{ID: "cap-mine/my-req/my-scenario"}}}
		got, err := UngatedInFlight(context.Background(), "openspec/changes", "base", nil, covered)
		require.NoError(t, err)
		assert.Empty(t, got, "the marker is the whole point: a covered scenario is not a finding")
	})

	t.Run("a scenario already canonical is left to the canonical gate", func(t *testing.T) {
		canonical := map[string]struct{}{"cap-mine/my-req/my-scenario": {}}
		got, err := UngatedInFlight(context.Background(), "openspec/changes", "base", canonical, nil)
		require.NoError(t, err)
		assert.Empty(t, got,
			"a MODIFIED requirement restates the headings it keeps, so most of a delta is canonical and already gated")
	})

	t.Run("editing a requirement does not gate the scenarios it already had", func(t *testing.T) {
		// The distinction between ADDED and merely touched, which review caught. computeNewCodeScenarioIDs promotes every
		// scenario under a requirement whose prose changed, which is right for the canonical gate because those scenarios are
		// gated anyway. Here it would attribute a sibling somebody else left unmarked to whoever next edits that requirement's
		// wording, which is the branch-scoping wedge one level in.
		edited := strings.Join([]string{
			"# Cap", "", "## ADDED Requirements", "",
			"### Requirement: Their req", "",
			"The system SHALL do the thing, stated more precisely than before.", "",
			"#### Scenario: Their scenario", "",
			"- WHEN x THEN y", "",
		}, "\n")
		writeInFlightDelta(t, changes, "someone-elses", "cap-other", edited)
		runGit(t, dir, "add", ".")
		runGit(t, dir, "commit", "--quiet", "-m", "reword their requirement")

		touched, err := computeNewCodeScenarioIDs(context.Background(), "openspec/changes", "base")
		require.NoError(t, err)
		require.Contains(t, touched, "cap-other/their-req/their-scenario",
			"the premise: the diff scope DOES promote it, which is why the gate has to narrow further")

		got, err := UngatedInFlight(context.Background(), "openspec/changes", "base", nil, nil)
		require.NoError(t, err)
		ids := make([]string, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
		}
		assert.NotContains(t, ids, "cap-other/their-req/their-scenario",
			"it was already in the delta at the merge base, so this branch did not introduce it")
		assert.Contains(t, ids, "cap-mine/my-req/my-scenario", "and the one this branch did add is still gated")
	})

	t.Run("a scenario another delta already carried is not blamed on this branch", func(t *testing.T) {
		// Concurrent MODIFIED restatements of one requirement must be identical, so the same ID legitimately appears in several
		// delta files. A branch adding a delta that restates a requirement another delta already carries would, with a baseline
		// read only from the files it changed, find that ID touched and absent from the baseline, and be blamed for a scenario
		// that was already there unmarked. Review caught this; the baseline is read from every delta at the merge base.
		restating := normativeDelta("Their req", "Their scenario")
		writeInFlightDelta(t, changes, "my-restatement", "cap-other", restating)
		runGit(t, dir, "add", ".")
		runGit(t, dir, "commit", "--quiet", "-m", "restate their requirement in my own delta")

		got, err := UngatedInFlight(context.Background(), "openspec/changes", "base", nil, nil)
		require.NoError(t, err)
		ids := make([]string, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
		}
		assert.NotContains(t, ids, "cap-other/their-req/their-scenario",
			"the ID was already declared by an untouched delta at the merge base, so this branch did not introduce it")
	})

	t.Run("an absolute changes-dir still scopes against the merge base", func(t *testing.T) {
		// resolvePathFlag hands back an absolute path whenever the caller sets --changes-dir, and review read that as a defect:
		// git pathspecs are repo-relative, so an absolute one would match nothing and the gate would report nothing while
		// appearing to have run. git in fact accepts an absolute pathspec inside the repository, so there is nothing to convert.
		// The case is pinned here anyway, because it is worth knowing if that ever stops being true, and because TMPDIR on macOS
		// reaches this repository through a symlink, which is where a conversion would have gone wrong.
		got, err := UngatedInFlight(context.Background(), filepath.Join(dir, "openspec", "changes"), "base", nil, nil)
		require.NoError(t, err)
		ids := make([]string, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
		}
		assert.Contains(t, ids, "cap-mine/my-req/my-scenario", "an absolute path must gate exactly as a relative one does")
	})

	t.Run("a branch that touched no delta gates nothing", func(t *testing.T) {
		got, err := UngatedInFlight(context.Background(), "openspec/changes", "HEAD", nil, nil)
		require.NoError(t, err)
		assert.Empty(t, got, "no delta changed against this base, so there is nothing this branch introduced")
	})
}

// TestUngatedInFlight_GitFailureIsReturned pins that the plumbing failure reaches the caller rather than being swallowed.
//
// Swallowing it is the specific way this class of gate fails silently: the required check passes while enforcing nothing, which
// is what it exists to prevent. runCheck turns this into exit 2.
func TestUngatedInFlight_GitFailureIsReturned(t *testing.T) {
	t.Parallel()
	_, err := UngatedInFlight(context.Background(), t.TempDir(), "--not-a-ref", nil, nil)
	require.Error(t, err)
}

// TestCollectScenarioIDs pins the failure contract the branch-attribution rests on.
//
// A read failure must propagate rather than be skipped. Skipping it would leave the file's scenarios out of the baseline, and a
// scenario absent from the baseline is one the gate blames on this branch: an infrastructure failure would become a false
// accusation, which is worse than the exit-2 it should be. No repository can produce that failure, because every path handed to
// the reader was listed at the revision being read, so the reader is a parameter.
func TestCollectScenarioIDs(t *testing.T) {
	t.Parallel()

	delta := normativeDelta("A req", "A scenario")

	t.Run("declares what the deltas carry", func(t *testing.T) {
		t.Parallel()
		got, err := collectScenarioIDs(
			[]string{"openspec/changes/c/specs/cap-a/spec.md"},
			func(string) (string, error) { return delta, nil },
		)
		require.NoError(t, err)
		assert.Contains(t, got, "cap-a/a-req/a-scenario")
	})

	t.Run("skips the archive and non-spec files without reading them", func(t *testing.T) {
		t.Parallel()
		var read []string
		got, err := collectScenarioIDs(
			[]string{
				"openspec/changes/archive/2026-01-01-old/specs/cap-b/spec.md",
				"openspec/changes/c/proposal.md",
			},
			func(f string) (string, error) { read = append(read, f); return delta, nil },
		)
		require.NoError(t, err)
		assert.Empty(t, got)
		assert.Empty(t, read, "an archived delta is canonical already, and a proposal is not a spec")
	})

	t.Run("a read failure propagates rather than dropping the file", func(t *testing.T) {
		t.Parallel()
		_, err := collectScenarioIDs(
			[]string{"openspec/changes/c/specs/cap-a/spec.md"},
			func(string) (string, error) { return "", errors.New("git timed out") },
		)
		require.Error(t, err, "dropping it would put the file's scenarios outside the baseline and blame this branch for them")
		assert.Contains(t, err.Error(), "git timed out")
	})
}

// TestInFlightScenarios_ChangeWithoutADelta pins the shape the traversal this replaced tolerated: a change folder carrying a
// proposal and tasks and no delta at all, which is what a tooling or documentation change ships. Failing on it would take
// spectrace down on a legitimate change rather than gating anything.
func TestInFlightScenarios_ChangeWithoutADelta(t *testing.T) {
	t.Parallel()
	changes := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(changes, "docs-only"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(changes, "docs-only", "proposal.md"), []byte("# Why\n"), 0o600))
	writeInFlightDelta(t, changes, "with-delta", "cap-a", normativeDelta("A req", "A scenario"))

	got, err := InFlightScenarios(changes)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "cap-a/a-req/a-scenario", got[0].ID)
}
