package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseModifiedRequirementScenarios covers the loader behind the retired-scenario exemption: it records the scenario slugs a
// `## MODIFIED Requirements` restatement lists, per requirement, and records nothing for the sections and shapes that must not
// grant an exemption.
func TestParseModifiedRequirementScenarios(t *testing.T) {
	t.Parallel()

	t.Run("records the scenarios a MODIFIED restatement lists", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "make-monitor-selectable", "web-ui", `## MODIFIED Requirements

### Requirement: Detection configuration admin views
The UI SHALL offer every mode.

#### Scenario: Monitor is an operator-selectable mode
- **THEN** all three are offered

#### Scenario: An operator adds an exclusion from the UI
- **THEN** it is created
`)
		got, err := parseModifiedRequirementScenarios(changes)
		require.NoError(t, err)
		require.Contains(t, got, "web-ui/detection-configuration-admin-views")
		assert.Equal(t, map[string]struct{}{
			"monitor-is-an-operator-selectable-mode":    {},
			"an-operator-adds-an-exclusion-from-the-ui": {},
		}, got["web-ui/detection-configuration-admin-views"])
	})

	t.Run("ADDED and REMOVED requirements grant no exemption", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "mixed", "web-ui", `## ADDED Requirements

### Requirement: Brand new thing
It SHALL be new.

#### Scenario: The new thing works
- **THEN** it works

## REMOVED Requirements

### Requirement: Retired thing
**Reason**: gone.
`)
		got, err := parseModifiedRequirementScenarios(changes)
		require.NoError(t, err)
		assert.Empty(t, got, "only a MODIFIED restatement replaces a scenario list")
	})

	t.Run("a requirement listing no scenarios is not recorded", func(t *testing.T) {
		t.Parallel()
		// The dangerous shape: registering an empty set would exempt every one of that requirement's canonical scenarios. It is
		// rejected by `openspec validate --strict`, but a delta being written has it until the author types the scenarios.
		changes := t.TempDir()
		writeChangeSpec(t, changes, "half-written", "web-ui", `## MODIFIED Requirements

### Requirement: Detection configuration admin views
The UI SHALL do something.
`)
		got, err := parseModifiedRequirementScenarios(changes)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("a section merely starting with MODIFIED is not a restatement", func(t *testing.T) {
		t.Parallel()
		changes := t.TempDir()
		writeChangeSpec(t, changes, "prose", "web-ui", `## MODIFIED Behaviour Notes

### Requirement: Detection configuration admin views
Prose about the change.

#### Scenario: Something
- **THEN** something
`)
		got, err := parseModifiedRequirementScenarios(changes)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("two changes restating one requirement contribute a union", func(t *testing.T) {
		t.Parallel()
		// More conservative than the archive, which applies them in sequence so the last list wins. A scenario either change still
		// lists is one this gate keeps demanding a marker for, which is the safe direction for an exemption.
		changes := t.TempDir()
		writeChangeSpec(t, changes, "first", "web-ui", `## MODIFIED Requirements

### Requirement: Detection configuration admin views
The UI SHALL do one thing.

#### Scenario: Kept by the first
- **THEN** yes
`)
		writeChangeSpec(t, changes, "second", "web-ui", `## MODIFIED Requirements

### Requirement: Detection configuration admin views
The UI SHALL do another thing.

#### Scenario: Kept by the second
- **THEN** yes
`)
		got, err := parseModifiedRequirementScenarios(changes)
		require.NoError(t, err)
		assert.Equal(t, map[string]struct{}{
			"kept-by-the-first":  {},
			"kept-by-the-second": {},
		}, got["web-ui/detection-configuration-admin-views"])
	})

	t.Run("no changes tree yields an empty set rather than an error", func(t *testing.T) {
		t.Parallel()
		got, err := parseModifiedRequirementScenarios(t.TempDir() + "/absent")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// TestFilterOutRetiredScenarios covers the filter: a canonical scenario a MODIFIED restatement omits is exempted and named, one it
// lists is kept, and a requirement no change modifies is untouched.
func TestFilterOutRetiredScenarios(t *testing.T) {
	t.Parallel()

	scenarios := []Scenario{
		{ID: "web-ui/admin-views/kept", SpecDir: "web-ui", Requirement: "Admin views", Title: "Kept"},
		{ID: "web-ui/admin-views/dropped", SpecDir: "web-ui", Requirement: "Admin views", Title: "Dropped"},
		{ID: "web-ui/other-thing/untouched", SpecDir: "web-ui", Requirement: "Other thing", Title: "Untouched"},
	}

	t.Run("exempts only the scenario the restatement omits, and names it", func(t *testing.T) {
		t.Parallel()
		kept, retired := filterOutRetiredScenarios(scenarios, map[string]map[string]struct{}{
			"web-ui/admin-views": {"kept": {}},
		})
		assert.Equal(t, []string{"web-ui/admin-views/dropped"}, retired)
		var ids []string
		for _, s := range kept {
			ids = append(ids, s.ID)
		}
		assert.Equal(t, []string{"web-ui/admin-views/kept", "web-ui/other-thing/untouched"}, ids,
			"a requirement no change modifies keeps every scenario")
	})

	t.Run("no modifications leaves the set alone", func(t *testing.T) {
		t.Parallel()
		kept, retired := filterOutRetiredScenarios(scenarios, nil)
		assert.Empty(t, retired)
		assert.Len(t, kept, len(scenarios))
	})
}
