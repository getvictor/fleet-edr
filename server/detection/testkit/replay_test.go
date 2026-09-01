package testkit

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FixturePaths is the single definition of "what counts as a fixture" for three gates: the replay harness, the catalog's coverage
// gate, and its dispatch-equivalence gate. Its recursion is load-bearing and, until these tests, was unprotected: every fixture in
// the tree happens to sit directly under its rule directory, so a one-level implementation would leave the whole suite green while
// quietly reintroducing the bypass where a nested fixture is replayed but skipped by dispatch equivalence.
func TestFixturePaths(t *testing.T) {
	t.Parallel()

	t.Run("finds fixtures nested below the rule directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "positive_top.json"), `{"events":[]}`)
		write(t, filepath.Join(dir, "deep", "positive_nested.json"), `{"events":[]}`)
		write(t, filepath.Join(dir, "deep", "deeper", "negative_further.json"), `{"events":[]}`)

		got, err := FixturePaths(dir)
		require.NoError(t, err)
		assert.Equal(t, []string{
			filepath.Join(dir, "deep", "deeper", "negative_further.json"),
			filepath.Join(dir, "deep", "positive_nested.json"),
			filepath.Join(dir, "positive_top.json"),
		}, got, "every depth is discovered, and the order is sorted so callers are deterministic")
	})

	// WalkDir's own order is depth-first lexical, which USUALLY matches a sort of the full paths, so a naive test cannot tell the
	// two apart. It diverges when a file and a directory share a prefix: walk visits the directory `a` before the file `a.json`,
	// while sorted paths put `a.json` first ('.' sorts before '/'). Without this case, deleting the sort leaves the suite green.
	t.Run("orders results by path even where the walk order differs", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "a.json"), `{"events":[]}`)
		write(t, filepath.Join(dir, "a", "b.json"), `{"events":[]}`)

		got, err := FixturePaths(dir)
		require.NoError(t, err)
		assert.Equal(t, []string{
			filepath.Join(dir, "a.json"),
			filepath.Join(dir, "a", "b.json"),
		}, got, "sorted by full path, not left in walk order")
	})

	t.Run("ignores files that are not fixtures", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "positive_real.json"), `{"events":[]}`)
		write(t, filepath.Join(dir, "README.md"), "not a fixture")
		write(t, filepath.Join(dir, "notes.json.bak"), "not a fixture either")

		got, err := FixturePaths(dir)
		require.NoError(t, err)
		assert.Equal(t, []string{filepath.Join(dir, "positive_real.json")}, got)
	})

	// Reported rather than flattened to an empty list, because "this rule has no fixtures" and "this rule's fixtures moved" are
	// different problems and only the caller knows which one it is gating on. The catalog's coverage gate relies on telling them
	// apart.
	t.Run("a missing directory is an error, not an empty list", func(t *testing.T) {
		t.Parallel()
		got, err := FixturePaths(filepath.Join(t.TempDir(), "no-such-rule"))
		require.Error(t, err)
		require.ErrorIs(t, err, fs.ErrNotExist)
		assert.Empty(t, got)
	})
}

func TestLoadFixture(t *testing.T) {
	t.Parallel()

	t.Run("decodes events and expected findings", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "positive.json")
		write(t, path, `{"events":[{"event_id":"e1","event_type":"exec"}],
			"expected_findings":[{"rule_id":"r","severity":"high"}]}`)

		c, err := LoadFixture(path)
		require.NoError(t, err)
		require.Len(t, c.Events, 1)
		assert.Equal(t, "e1", c.Events[0].EventID)
		require.Len(t, c.ExpectedFindings, 1)
		assert.Equal(t, "r", c.ExpectedFindings[0].RuleID)
	})

	// The path is in the error because a malformed fixture is found by a gate looping over dozens of them, and "invalid character"
	// with no filename sends the reader hunting.
	t.Run("a malformed fixture names the file that failed", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "broken.json")
		write(t, path, `{"events": [`)

		_, err := LoadFixture(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "broken.json")
	})

	t.Run("a missing file names the file that failed", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "absent.json")

		_, err := LoadFixture(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "absent.json")
	})
}

func write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}
