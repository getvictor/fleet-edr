package main

import (
	"context"
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
