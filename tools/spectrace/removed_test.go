package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseRemovedRequirementKeys covers the release-time-archive exemption loader: it collects "<capability>/<req-slug>"
// keys from `## REMOVED Requirements` sections of in-flight deltas, ignores ADDED/MODIFIED requirements, skips the archive
// subtree, and degrades to an empty set when there is no changes tree.
func TestParseRemovedRequirementKeys(t *testing.T) {
	t.Parallel()
	t.Run("collects requirement keys under a REMOVED section and ignores ADDED ones", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "drop-keyed-hash", "agent-enrollment", `## ADDED Requirements

### Requirement: Tokens are self-validating
The server SHALL issue self-validating tokens.

#### Scenario: Issued token verifies
- **THEN** it verifies

## REMOVED Requirements

### Requirement: Host tokens are stored and verified with a fast keyed hash
**Reason**: Superseded by self-validating signed tokens.
`)
		keys, err := parseRemovedRequirementKeys(changes)
		require.NoError(t, err)
		assert.Contains(t, keys, "agent-enrollment/host-tokens-are-stored-and-verified-with-a-fast-keyed-hash")
		assert.NotContains(t, keys, "agent-enrollment/tokens-are-self-validating", "ADDED requirements are not exemptions")
		assert.Len(t, keys, 1)
	})

	t.Run("a REMOVED section other than 'REMOVED Requirements' is not treated as a removal", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "weird", "agent-enrollment", `## REMOVED Notes

### Requirement: Should not be exempted
**Reason**: this lives under a non-canonical REMOVED heading.
`)
		keys, err := parseRemovedRequirementKeys(changes)
		require.NoError(t, err)
		assert.Empty(t, keys, "only the exact '## REMOVED Requirements' heading drives exemptions")
	})

	t.Run("a stray spec.md outside the specs/ subtree contributes no keys", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		// A spec.md placed directly under the change folder (not under specs/<capability>/) must be ignored so it cannot
		// derive a bogus capability and exempt scenarios it shouldn't.
		strayDir := filepath.Join(changes, "stray-change")
		require.NoError(t, os.MkdirAll(strayDir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(strayDir, "spec.md"), []byte(`## REMOVED Requirements

### Requirement: Misplaced removal
**Reason**: not under specs/.
`), 0o600))
		keys, err := parseRemovedRequirementKeys(changes)
		require.NoError(t, err)
		assert.Empty(t, keys, "only spec.md under <change>/specs/<capability>/ is parsed")
	})

	t.Run("archived removals are not counted (already applied into live specs)", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		archived := filepath.Join(changes, archiveDirName, "2026-01-01-old", "specs", "agent-enrollment")
		require.NoError(t, os.MkdirAll(archived, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(archived, "spec.md"), []byte(`## REMOVED Requirements

### Requirement: Old retired thing
**Reason**: gone.
`), 0o600))
		keys, err := parseRemovedRequirementKeys(changes)
		require.NoError(t, err)
		assert.Empty(t, keys, "archived REMOVED requirements are already gone from live specs")
	})

	t.Run("missing or empty changes dir yields an empty set", func(t *testing.T) {
		t.Parallel()
		keys, err := parseRemovedRequirementKeys(filepath.Join(t.TempDir(), "nope"))
		require.NoError(t, err)
		assert.Empty(t, keys)

		keys, err = parseRemovedRequirementKeys("")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

// TestFilterOutRemovedRequirements pins the gate-set filter: a canonical scenario whose parent requirement is in the
// removed-keys set is dropped, others are kept, and an empty key set is a no-op pass-through.
func TestFilterOutRemovedRequirements(t *testing.T) {
	t.Parallel()
	scenarios := []Scenario{
		{ID: "agent-enrollment/fast-keyed-hash/a", SpecDir: "agent-enrollment", Requirement: "Fast keyed hash", Normative: true},
		{ID: "agent-enrollment/fast-keyed-hash/b", SpecDir: "agent-enrollment", Requirement: "Fast keyed hash", Normative: true},
		{ID: "agent-enrollment/signed-tokens/c", SpecDir: "agent-enrollment", Requirement: "Signed tokens", Normative: true},
	}

	t.Run("drops scenarios under a removed requirement, keeps the rest", func(t *testing.T) {
		t.Parallel()
		removed := map[string]struct{}{"agent-enrollment/fast-keyed-hash": {}}
		got := filterOutRemovedRequirements(scenarios, removed)
		require.Len(t, got, 1)
		assert.Equal(t, "agent-enrollment/signed-tokens/c", got[0].ID)
	})

	t.Run("empty key set is a pass-through", func(t *testing.T) {
		t.Parallel()
		got := filterOutRemovedRequirements(scenarios, map[string]struct{}{})
		assert.Len(t, got, 3)
	})
}
