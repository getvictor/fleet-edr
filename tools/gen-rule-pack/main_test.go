package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// packDir is the committed pack, relative to this package's directory.
const packDir = "../../docs/rules"

func committedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(packDir)
	require.NoError(t, err, "the committed pack must exist; run `go run ./tools/gen-rule-pack`")

	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(packDir, e.Name())) //nolint:gosec // fixed in-repo path
		require.NoError(t, err)
		out[strings.TrimSuffix(e.Name(), ".yml")] = body
	}
	return out
}

// spec:server-detection-rules-engine/the-exported-rule-pack-matches-the-registered-detections/a-rule-added-without-regenerating-the-pack-fails-the-build
// spec:server-detection-rules-engine/the-exported-rule-pack-matches-the-registered-detections/a-stale-rule-file-fails-the-build
//
// TestPackHasNoDrift is the gate the issue asks for: a rule added, renamed, or documented differently without regenerating the
// pack fails here rather than shipping a catalog that disagrees with the code.
//
// It compares content, not just the file list. A stale file is the more dangerous half: a missing one is obvious the moment
// someone looks for it, whereas a file whose description or severity silently lags the rule reads as authoritative and is wrong.
func TestPackHasNoDrift(t *testing.T) {
	t.Parallel()

	want, err := rulesbootstrap.ExportPack()
	require.NoError(t, err)
	require.NotEmpty(t, want, "no detections registered")

	got := committedFiles(t)

	wantIDs := make([]string, 0, len(want))
	for id := range want {
		wantIDs = append(wantIDs, id)
	}
	gotIDs := make([]string, 0, len(got))
	for id := range got {
		gotIDs = append(gotIDs, id)
	}
	sort.Strings(wantIDs)
	sort.Strings(gotIDs)
	require.Equal(t, wantIDs, gotIDs,
		"the committed pack does not cover exactly the registered detections; run `go run ./tools/gen-rule-pack`")

	for id, body := range want {
		assert.Equal(t, string(append([]byte(header), body...)), string(got[id]),
			"%s.yml is stale; run `go run ./tools/gen-rule-pack`", id)
	}
}

// spec:server-detection-rules-engine/detections-are-exportable-as-declarative-rule-files/a-non-detection-has-no-rule-file
//
// TestPackExcludesNonDetections pins the #775 boundary at the artifact level. The registry still holds a projection and a health
// signal, and neither has detection logic, a tuning surface, or an adversary claim to describe. A rule file for either would
// misrepresent all three.
func TestPackExcludesNonDetections(t *testing.T) {
	t.Parallel()

	got := committedFiles(t)
	for _, id := range []string{"application_control_block", "sensor_recovery_failed"} {
		assert.NotContains(t, got, id, "%s is a non-detection and must not be exported as a rule", id)
	}
}

// TestPackFilesCarryTheGeneratedHeader guards the one thing a reader of a single file, who has never seen this generator, needs
// to know: that hand-edits do not survive.
func TestPackFilesCarryTheGeneratedHeader(t *testing.T) {
	t.Parallel()

	for id, body := range committedFiles(t) {
		assert.True(t, strings.HasPrefix(string(body), header), "%s.yml is missing the generated-file header", id)
	}
}

// TestGenerateWritesThePack drives the writer end to end against a temp directory, so the file naming and the header prepend are
// covered rather than only the rendering underneath them.
func TestGenerateWritesThePack(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	n, err := generate(dir)
	require.NoError(t, err)
	assert.Positive(t, n)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, n, "one file per rendered rule")

	body, err := os.ReadFile(filepath.Join(dir, "credential_keychain_dump.yml")) //nolint:gosec // temp dir under test control
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(body), header))
	assert.Contains(t, string(body), "title: Keychain credential dump")
}

// TestGenerateRejectsAnUnwritableDestination covers the error path, so a failure to write is surfaced rather than reported as a
// successful run that produced nothing.
func TestGenerateRejectsAnUnwritableDestination(t *testing.T) {
	t.Parallel()

	// A path whose parent is a regular file cannot be created as a directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	_, err := generate(filepath.Join(blocker, "pack"))
	require.Error(t, err)
}
