package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveRepoPath_AbsoluteIsVerbatim pins rule 1: an absolute path is returned unchanged. The function MUST NOT reach for git
// at all in this case; we don't want a spectrace invocation against an absolute path to fail on a non-git directory or a hung
// credential prompt that the underlying git rev-parse subprocess would otherwise trigger.
func TestResolveRepoPath_AbsoluteIsVerbatim(t *testing.T) {
	abs := t.TempDir()
	assert.Equal(t, abs, resolveRepoPath(abs))
}

// TestResolveRepoPath_CwdRelativeShortCircuits pins rule 2: when the path already resolves relative to cwd, the
// function returns it verbatim. Doing this avoids second-guessing callers who supply `--specs-dir=./local-fixture` from
// inside a nested package; their literal `./` is what they want, even if the same name also exists at the repo root.
func TestResolveRepoPath_CwdRelativeShortCircuits(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "exists"), 0o750))
	t.Chdir(dir)
	assert.Equal(t, "exists", resolveRepoPath("exists"))
}

// TestResolveRepoPath_PromotesToRepoRoot pins rule 3: when the path doesn't resolve cwd-relative but exists relative to
// the repo top-level, return the joined path. We model this by initialising a fake git repo, dropping a file at the
// root, then cd'ing into a subdirectory and asking the resolver to find the file by its relative name.
func TestResolveRepoPath_PromotesToRepoRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := setupGitRepo(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "openspec", "specs"), 0o750))
	sub := filepath.Join(root, "tools", "spectrace")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	t.Chdir(sub)
	got := resolveRepoPath("openspec/specs")
	want := filepath.Join(root, "openspec", "specs")
	// macOS adds a /private prefix to t.TempDir results in some contexts; canonicalise both sides via filepath.EvalSymlinks.
	gotReal, _ := filepath.EvalSymlinks(got)
	wantReal, _ := filepath.EvalSymlinks(want)
	assert.Equal(t, wantReal, gotReal)
}

// TestResolveRepoPath_UnresolvableReturnsOriginal pins rule 4: when the path doesn't resolve cwd-relative and the repo
// root either can't be found or doesn't have the path either, the function returns the original. The downstream parser
// then emits a deterministic "no such file" error against the user's input, which is the right shape for catching typos.
func TestResolveRepoPath_UnresolvableReturnsOriginal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := setupGitRepo(t)
	t.Chdir(root)
	assert.Equal(t, "definitely-not-here", resolveRepoPath("definitely-not-here"))
}

// TestResolveDefaultRepoPath_PromotesDotToRepoRoot pins the more aggressive behaviour for unset flags. The literal `.` trivially
// resolves cwd-relative, so resolveRepoPath would short-circuit at rule 2 and leave a default `--root .` scan scoped to the
// tools/spectrace subdirectory. The default-only variant skips the cwd check so the scan widens to the whole repo, which is the
// actual intent of running `spectrace check` from any directory.
func TestResolveDefaultRepoPath_PromotesDotToRepoRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := setupGitRepo(t)
	sub := filepath.Join(root, "tools", "spectrace")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	t.Chdir(sub)
	got := resolveDefaultRepoPath(".")
	gotReal, _ := filepath.EvalSymlinks(got)
	rootReal, _ := filepath.EvalSymlinks(root)
	assert.Equal(t, rootReal, gotReal,
		"a `.` default from a subdirectory must widen to the repo root, not stay scoped to the subdir")
}

// TestResolvePathFlag_HonoursUserExplicitness pins the switch between the two resolvers based on whether the operator supplied the
// flag. An explicit `--root .` from a subdirectory means "literally cwd" and must not be widened to the repo root; a default
// `--root .` means "the natural scope" and gets widened.
func TestResolvePathFlag_HonoursUserExplicitness(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := setupGitRepo(t)
	sub := filepath.Join(root, "tools", "spectrace")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	t.Chdir(sub)

	t.Run("explicit value stays cwd-relative", func(t *testing.T) {
		assert.Equal(t, ".", resolvePathFlag(".", true))
	})
	t.Run("default value widens to repo root", func(t *testing.T) {
		got := resolvePathFlag(".", false)
		gotReal, _ := filepath.EvalSymlinks(got)
		rootReal, _ := filepath.EvalSymlinks(root)
		assert.Equal(t, rootReal, gotReal)
	})
}

// TestUserSetFlagNames covers the small helper that wraps fs.Visit. We supply one flag explicitly and confirm only that
// name appears in the resulting set; the unset flags must NOT appear, which is the property resolvePathFlag depends on.
func TestUserSetFlagNames(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("specs-dir", "default-a", "")
	fs.String("root", "default-b", "")
	require.NoError(t, fs.Parse([]string{"--specs-dir", "explicit-a"}))
	got := userSetFlagNames(fs)
	assert.True(t, got["specs-dir"])
	assert.False(t, got["root"])
}

// setupGitRepo creates a transient git repo and returns its absolute root path. Tests use this when they need
// gitTopLevel to succeed in isolation from the surrounding fleet-edr worktree.
func setupGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "user.email", "spectrace@example.test"},
		{"config", "user.name", "spectrace test"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // args are literal
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}
