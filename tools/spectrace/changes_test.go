package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeChangeSpec writes a delta spec.md for capability under changesDir/<change>/specs/<capability>/spec.md, creating the
// directory tree. Mirrors the real openspec/changes/<change>/specs/<cap>/spec.md layout.
func writeChangeSpec(t *testing.T, changesDir, change, capability, body string) {
	t.Helper()
	dir := filepath.Join(changesDir, change, "specs", capability)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "spec.md"), []byte(body), 0o600))
}

// TestParseChangeScenarioIDs covers the WIP-reference loader: it must collect scenario IDs from in-flight proposals (so a
// test can reference a not-yet-archived scenario without spectrace flagging a dangling reference), tolerate a MODIFIED
// requirement that repeats a live heading (duplicates collapse, no error), and degrade to an empty set when there is no
// changes tree.
func TestParseChangeScenarioIDs(t *testing.T) {
	t.Parallel()
	t.Run("collects IDs from a change delta and slugs them canonically", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "add-widget", "web-ui", `## ADDED Requirements

### Requirement: Widget is gated
The UI SHALL gate the widget.

#### Scenario: Widget hidden without permission
- **WHEN** the operator lacks the action
- **THEN** the widget is hidden
`)
		ids, err := parseChangeScenarioIDs(changes)
		require.NoError(t, err)
		assert.Contains(t, ids, "web-ui/widget-is-gated/widget-hidden-without-permission")
	})

	t.Run("a MODIFIED requirement repeating a heading collapses without a duplicate error", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		// Two proposals touch the same capability + scenario heading. buildCanonicalSet would reject this for live
		// specs; the WIP loader must not, because MODIFIED requirements intentionally repeat live headings.
		body := `## MODIFIED Requirements

### Requirement: Current-user lookup
The system SHALL return the session.

#### Scenario: Session probe while logged out
- **THEN** the server returns 401
`
		writeChangeSpec(t, changes, "change-a", "ui-authentication-session", body)
		writeChangeSpec(t, changes, "change-b", "ui-authentication-session", body)
		ids, err := parseChangeScenarioIDs(changes)
		require.NoError(t, err)
		assert.Contains(t, ids, "ui-authentication-session/current-user-lookup/session-probe-while-logged-out")
		assert.Len(t, ids, 1, "the repeated heading collapses to a single set entry")
	})

	t.Run("scenarios under the archive subtree are excluded", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		// An in-flight proposal: its scenario IDs ARE valid WIP marker targets.
		writeChangeSpec(t, changes, "in-flight", "web-ui", `## ADDED Requirements

### Requirement: New thing
The UI SHALL do a new thing.

#### Scenario: New thing happens
- **THEN** it happens
`)
		// An archived (already-applied) change lives under archive/. Its delta IDs are represented in the live
		// specs already, so they must NOT be re-counted here (else a later live rename would leave the stale ID
		// falsely valid).
		archived := filepath.Join(changes, archiveDirName, "2026-01-01-old-change", "specs", "web-ui")
		require.NoError(t, os.MkdirAll(archived, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(archived, "spec.md"), []byte(`## MODIFIED Requirements

### Requirement: Old thing
The UI SHALL do an old thing.

#### Scenario: Old thing happened
- **THEN** it happened
`), 0o600))

		ids, err := parseChangeScenarioIDs(changes)
		require.NoError(t, err)
		assert.Contains(t, ids, "web-ui/new-thing/new-thing-happens")
		assert.NotContains(t, ids, "web-ui/old-thing/old-thing-happened", "archived change IDs must not count as WIP targets")
	})

	t.Run("missing changes dir yields an empty set, not an error", func(t *testing.T) {
		t.Parallel()
		ids, err := parseChangeScenarioIDs(filepath.Join(t.TempDir(), "does-not-exist"))
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("empty changesDir argument yields an empty set", func(t *testing.T) {
		t.Parallel()
		ids, err := parseChangeScenarioIDs("")
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("a regular file path is tolerated as empty, not an error", func(t *testing.T) {
		t.Parallel()
		f := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
		ids, err := parseChangeScenarioIDs(f)
		require.NoError(t, err)
		assert.Empty(t, ids)
	})
}
