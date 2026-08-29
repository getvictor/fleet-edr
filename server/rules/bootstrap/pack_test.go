package bootstrap

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/internal/export"
)

// packDir is the committed rule pack, relative to this package's directory.
//
// These tests live here, next to ExportPack, rather than beside the generator in tools/gen-rule-pack, for one reason: CI runs
// `./server/... ./internal/... ./test/integration/... ./test/scale/...` and does NOT run ./tools/.... A drift check that only
// runs locally is not a drift check, it is a suggestion, and the whole point of this guard is that a rule added, renamed, or
// re-documented without regenerating the pack fails the build.
const packDir = "../../../docs/rules"

func committedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(packDir)
	require.NoError(t, err, "the committed pack must exist; run `task docs:rule-pack`")

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
// TestPackHasNoDrift compares content, not just the file list. A stale file is the more dangerous half of drift: a missing one is
// obvious the moment someone looks for it, whereas a file whose description or severity silently lags the rule reads as
// authoritative and is wrong.
func TestPackHasNoDrift(t *testing.T) {
	t.Parallel()

	want, err := ExportPack()
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
		"the committed pack does not cover exactly the registered detections; run `task docs:rule-pack`")

	for id, body := range want {
		assert.Equal(t, string(body), string(got[id]), "%s.yml is stale; run `task docs:rule-pack`", id)
	}
}

// spec:server-detection-rules-engine/detections-are-exportable-as-declarative-rule-files/a-non-detection-has-no-rule-file
//
// TestPackExcludesNonDetections pins the #775 boundary at the artifact level. The registry still holds a projection and a health
// signal, and neither has detection logic, a tuning surface, or an adversary claim to describe.
func TestPackExcludesNonDetections(t *testing.T) {
	t.Parallel()

	got := committedFiles(t)
	for _, id := range []string{"application_control_block", "sensor_recovery_failed"} {
		assert.NotContains(t, got, id, "%s is a non-detection and must not be exported as a rule", id)
	}
}

// TestPackFilesCarryTheGeneratedHeader guards the one thing a reader of a single file, who has never seen the generator, needs to
// know: that hand-edits do not survive.
func TestPackFilesCarryTheGeneratedHeader(t *testing.T) {
	t.Parallel()

	for id, body := range committedFiles(t) {
		assert.True(t, strings.HasPrefix(string(body), export.Header), "%s.yml is missing the generated-file header", id)
	}
}

// TestServedRuleIsThePackFileWithoutItsHeader pins the exact relationship between the two surfaces, which is a header apart
// rather than byte-identical.
//
// They differ on purpose. The header tells a reader of the committed file not to hand-edit it, which is true of a generated
// artifact in the repository and false of an operator's own download. Pinning the relationship keeps that a decision rather than
// an accident, and catches either surface drifting from the one serialiser.
func TestServedRuleIsThePackFileWithoutItsHeader(t *testing.T) {
	t.Parallel()

	committed := committedFiles(t)
	require.Contains(t, committed, "credential_keychain_dump")

	for _, md := range CatalogOnly().List() {
		if md.ID != "credential_keychain_dump" {
			continue
		}
		served, err := export.Rule(md)
		require.NoError(t, err)
		assert.Equal(t, string(committed[md.ID]), export.Header+string(served))
		assert.NotContains(t, string(served), "Do not hand-edit", "the served document carries no generated-file header")
		return
	}
	t.Fatal("credential_keychain_dump is not registered")
}
