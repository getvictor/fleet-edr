package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubCommands stands in for the two external tools. It exists for the two states a real archive run cannot be asked for on
// demand: an ordering pass that refuses, and an `openspec archive` that fails on the third of five changes.
type stubCommands struct {
	sequence    []string
	sequenceErr error
	failOn      string
	archived    []string
}

func (s *stubCommands) order(context.Context) ([]string, error) {
	if s.sequenceErr != nil {
		return nil, s.sequenceErr
	}
	return s.sequence, nil
}

// archive records the attempt BEFORE it fails, so a test can tell "stopped at this change" from "never reached it".
func (s *stubCommands) archive(_ context.Context, change string) error {
	s.archived = append(s.archived, change)
	if change == s.failOn {
		return errors.New("openspec exited 1")
	}
	return nil
}

func TestArchiveAll(t *testing.T) {
	t.Parallel()

	// The sequence is deliberately NOT alphabetical in every case that archives: an implementation that sorted, or that walked
	// the changes directory, would pass a test whose fixture happened to be in alphabetical order already.
	const first, second, third = "m-unrelated", "z-introduces-it", "a-refines-it"

	for _, tc := range []struct {
		name         string
		stub         *stubCommands
		dryRun       bool
		wantErr      string
		wantArchived []string
		wantOut      []string
	}{
		{
			name:         "applies the order archive-order gave, not the alphabetical one",
			stub:         &stubCommands{sequence: []string{first, second, third}},
			wantArchived: []string{first, second, third},
			wantOut:      []string{"3 pending change(s)", "archived 3 change(s)"},
		},
		{
			name:         "an ordering failure archives nothing at all",
			stub:         &stubCommands{sequence: []string{first, second}, sequenceErr: errors.New("no safe order")},
			wantErr:      "no safe order; nothing was archived",
			wantArchived: nil,
		},
		{
			name:         "a failure partway stops rather than continuing down the list",
			stub:         &stubCommands{sequence: []string{first, second, third}, failOn: second},
			wantErr:      "archiving z-introduces-it failed after 1 of 3",
			wantArchived: []string{first, second},
		},
		{
			name:         "a dry run prints the sequence and archives nothing",
			stub:         &stubCommands{sequence: []string{first, second, third}},
			dryRun:       true,
			wantArchived: nil,
			wantOut:      []string{"1. " + first, "2. " + second, "3. " + third, "dry run, nothing archived"},
		},
		{
			name:    "an already-archived tree is a no-op rather than a failure",
			stub:    &stubCommands{},
			wantOut: []string{"no pending changes"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := archiveAll(t.Context(), tc.stub, tc.dryRun, &out)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.wantArchived, tc.stub.archived)
			for _, want := range tc.wantOut {
				assert.Contains(t, out.String(), want)
			}
		})
	}

	// The plan has to be readable before the first archive runs: after it, the working tree has moved and the only way back is
	// git. A run that printed its sequence only on the way out would be useless for stopping one.
	t.Run("prints the whole sequence before archiving the first change", func(t *testing.T) {
		t.Parallel()
		stub := &stubCommands{sequence: []string{first, second}}
		var out bytes.Buffer
		require.NoError(t, archiveAll(t.Context(), stub, false, &out))
		plan := out.String()
		assert.Less(t, strings.Index(plan, "2. "+second), strings.Index(plan, "[1/2] openspec archive "+first),
			"the last line of the plan must precede the first archive")
	})
}

func TestOrderFailure(t *testing.T) {
	t.Parallel()

	// Both statuses stop the run. They are separated only so the operator is sent to the right next step: exit 1 is a decision
	// nobody can make for them, and anything else is a tool failure to retry.
	for _, tc := range []struct {
		name     string
		exitWith string
		want     string
	}{
		{"a cycle names the human decision", "exit 1", "found no safe order"},
		{"a tool failure does not claim a cycle", "exit 2", "archive-order failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := exec.CommandContext(t.Context(), "sh", "-c", tc.exitWith).Run() //nolint:gosec // the script is a test literal
			require.Error(t, err)
			assert.ErrorContains(t, orderFailure(err), tc.want)
		})
	}

	t.Run("a command that never ran is a tool failure", func(t *testing.T) {
		t.Parallel()
		assert.ErrorContains(t, orderFailure(errors.New("executable file not found in $PATH")), "archive-order failed")
	})
}

func TestParseOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		out  string
		want []string
	}{
		{"one change per line", "b-first\na-second\n", []string{"b-first", "a-second"}},
		{"no trailing newline", "only", []string{"only"}},
		{"an empty list is no changes, not one empty name", "", nil},
		{"blank lines are skipped", "a\n\nb\n", []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, parseOrder([]byte(tc.out)))
		})
	}
}

// TestCommandArgv pins the two invocations. The argv is where the two flags that must not drift live: --porcelain, without which
// the caller would be parsing prose, and the --skip-specs that must NEVER appear, because it skips the merge into
// openspec/specs/** that is the entire purpose of the release archive.
func TestCommandArgv(t *testing.T) {
	t.Parallel()
	c := execCommands{root: "/repo", spectrace: "/repo/tmp/spectrace"}

	order := c.orderCmd(t.Context())
	assert.Equal(t, []string{"/repo/tmp/spectrace", "archive-order", "--porcelain"}, order.Args)
	assert.Equal(t, "/repo", order.Dir)

	archive := c.archiveCmd(t.Context(), "some-change")
	assert.Equal(t, []string{"openspec", "archive", "some-change", "-y"}, archive.Args)
	assert.Equal(t, "/repo", archive.Dir)
	assert.NotContains(t, archive.Args, "--skip-specs")
}

// writeChange writes one in-flight change's delta into a fixture tree, the same shape tools/spectrace parses.
func writeChange(t *testing.T, changesDir, change, body string) {
	t.Helper()
	dir := filepath.Join(changesDir, change, "specs", "cap")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// requirement builds one delta section. A MODIFIED entry needs a scenario: the parser drops one that lists none, on the reading
// that it is a delta mid-write, and an entry that never reaches the index cannot constrain anything.
func requirement(section, name, body string) string {
	return "# T\n\n## " + section + " Requirements\n\n### Requirement: " + name + "\n\nSHALL " + body +
		".\n\n#### Scenario: One\n\n- **THEN** it does\n"
}

// canonicalSpec writes a requirement into the fixture's canonical tree, which is what tells spectrace that a pending ADDED for it
// is re-introducing something rather than creating it.
func canonicalSpec(t *testing.T, root, name string) {
	t.Helper()
	dir := filepath.Join(root, "openspec", "specs", "cap")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	body := "# cap Specification\n\n## Purpose\n\nFixture.\n\n## Requirements\n\n### Requirement: " + name +
		"\n\nSHALL do the thing.\n\n#### Scenario: One\n\n- **THEN** it does\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// realSpectrace builds the actual ordering tool through the same path a release run does, so the end-to-end tests drive it
// rather than a re-implementation of it.
func realSpectrace(t *testing.T) string {
	t.Helper()
	// The test binary runs in tools/releasearchive; the package path resolves from the repository root.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	bin, cleanup, err := buildSpectrace(t.Context(), root, io.Discard)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return bin
}

// TestArchivesInTheOrderSpectracePrints is the end-to-end one: a real fixture tree, the real spectrace binary computing the
// order, the real --porcelain parse, and the real sequencing. Only the archive itself is stubbed, since running openspec would
// mutate the fixture rather than record what it was asked to do.
//
// The fixture is built so the safe order and the alphabetical one differ. Without that the test proves nothing: sorting the
// change directories, which is what the release checklist warned a human not to do, would pass it.
func TestArchivesInTheOrderSpectracePrints(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	changes := filepath.Join(root, "openspec", "changes")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "openspec", "specs"), 0o750))
	// z-introduces-it creates the requirement a-refines-it restates, so it must be archived first however the names sort.
	writeChange(t, changes, "z-introduces-it", requirement("ADDED", "The thing", "do the thing"))
	writeChange(t, changes, "a-refines-it", requirement("MODIFIED", "The thing", "do the thing, refined"))
	writeChange(t, changes, "m-unrelated", requirement("ADDED", "Another thing", "do something else"))

	var stdout, stderr bytes.Buffer
	recorder := &recordingArchive{execCommands: execCommands{root: root, spectrace: realSpectrace(t), stderr: &stderr}}
	require.NoError(t, archiveAll(t.Context(), recorder, false, &stdout))

	assert.Equal(t, []string{"m-unrelated", "z-introduces-it", "a-refines-it"}, recorder.archived,
		"the constrained order, which is not the alphabetical one")
	assert.Contains(t, stderr.String(), "must be archived before a-refines-it",
		"the constraint that shaped the order still reaches the operator")
}

// TestNoSafeOrderArchivesNothing is the same chain with a fixture that has no safe order: one change re-introduces a requirement
// another retires, and the canonical tree already holds it, so neither order gives both authors what their delta says.
func TestNoSafeOrderArchivesNothing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	canonicalSpec(t, root, "The thing")
	changes := filepath.Join(root, "openspec", "changes")
	writeChange(t, changes, "reintroduces-it", requirement("ADDED", "The thing", "do the thing"))
	writeChange(t, changes, "retires-it", "# T\n\n## REMOVED Requirements\n\n### Requirement: The thing\n")

	var stdout, stderr bytes.Buffer
	recorder := &recordingArchive{execCommands: execCommands{root: root, spectrace: realSpectrace(t), stderr: &stderr}}
	err := archiveAll(t.Context(), recorder, false, &stdout)

	require.ErrorContains(t, err, "found no safe order")
	require.ErrorContains(t, err, "nothing was archived")
	assert.Empty(t, recorder.archived, "a cycle must not archive the prefix spectrace managed to order")
	assert.Contains(t, stderr.String(), "No order satisfies all of them")
}

// recordingArchive runs the real ordering pass and records the archive calls instead of making them.
type recordingArchive struct {
	execCommands
	archived []string
}

func (r *recordingArchive) archive(_ context.Context, change string) error {
	r.archived = append(r.archived, change)
	return nil
}

// stubbornWriter fails after a set number of successful writes, which is what a broken pipe partway through the plan looks like.
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

// TestArchiveAllStopsOnATruncatedPlan covers the contract the plan exists for: the whole sequence is readable BEFORE the tree
// moves. A plan a broken pipe cut short while the archiving carried on would break exactly that while still reporting success,
// which is the failure printArchiveVerify refuses for its own report.
func TestArchiveAllStopsOnATruncatedPlan(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		wrote int
	}{
		{"the header fails", 0},
		{"a line partway through the plan fails", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := &stubCommands{sequence: []string{"m-unrelated", "z-introduces-it", "a-refines-it"}}
			err := archiveAll(t.Context(), stub, false, &stubbornWriter{ok: tc.wrote, err: errors.New("pipe closed")})
			require.ErrorContains(t, err, "pipe closed")
			require.ErrorContains(t, err, "nothing was archived")
			assert.Empty(t, stub.archived, "the plan is the operator's one chance to stop this, so a truncated one archives nothing")
		})
	}
}

// TestRunRejectsAPositionalArgument is the mistyped preview. `flag` stops at the first positional argument and leaves the rest
// unread, so `task release:archive -- dry-run` parses as no flags at all: without this refusal the operator asks for a preview
// and gets the archive. The check runs before spectrace is even built, so a refused run has done nothing whatsoever.
func TestRunRejectsAPositionalArgument(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a flag typed without its dashes", []string{"dry-run"}, `unexpected argument "dry-run"`},
		{"a stray word after a real flag", []string{"--dry-run", "later"}, `unexpected argument "later"`},
		{"a change name, which this command does not take", []string{"some-change"}, `unexpected argument "some-change"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			require.ErrorContains(t, run(t.Context(), tc.args, &stdout, &stderr), tc.want)
			assert.Empty(t, stdout.String(), "refused before anything was built, read, or archived")
		})
	}
}
