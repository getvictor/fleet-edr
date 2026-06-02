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
	t.Run("collects IDs from a change delta and slugs them canonically", func(t *testing.T) {
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

	t.Run("missing changes dir yields an empty set, not an error", func(t *testing.T) {
		ids, err := parseChangeScenarioIDs(filepath.Join(t.TempDir(), "does-not-exist"))
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("empty changesDir argument yields an empty set", func(t *testing.T) {
		ids, err := parseChangeScenarioIDs("")
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("a regular file path is tolerated as empty, not an error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
		ids, err := parseChangeScenarioIDs(f)
		require.NoError(t, err)
		assert.Empty(t, ids)
	})
}
