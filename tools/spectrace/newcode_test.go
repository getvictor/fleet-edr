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

// TestParseUnifiedDiffNewRanges pins the hunk-header parse. Each row exercises one shape the parser will see in the wild:
// implicit count (just `+a`), explicit count (`+a,b`), pure-deletion (`+a,0` — skipped), and a multi-hunk diff.
func TestParseUnifiedDiffNewRanges(t *testing.T) {
	cases := []struct {
		name string
		diff string
		want []lineRange
	}{
		{
			name: "single hunk implicit count is treated as 1",
			diff: "@@ -10 +12 @@\n+new line\n",
			want: []lineRange{{Start: 12, End: 12}},
		},
		{
			name: "single hunk explicit count",
			diff: "@@ -10,2 +12,3 @@\n+a\n+b\n+c\n",
			want: []lineRange{{Start: 12, End: 14}},
		},
		{
			name: "pure deletion is skipped",
			diff: "@@ -10,2 +12,0 @@\n-a\n-b\n",
			want: nil,
		},
		{
			name: "multiple hunks",
			diff: "@@ -1,3 +1,2 @@\n line\n-old\n line\n@@ -10,0 +12,2 @@\n+new1\n+new2\n",
			want: []lineRange{{Start: 1, End: 2}, {Start: 12, End: 13}},
		},
		{
			name: "diff with no hunks returns nil",
			diff: "diff --git a/x b/x\nindex abc..def 100644\n",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseUnifiedDiffNewRanges(tc.diff))
		})
	}
}

// TestAnyOverlap pins the inclusive-closed range intersection that computeNewCodeScenarioIDs uses to decide whether the scenario's
// body overlaps any diff hunk. Adjacency-not-overlap is a separate case row because off-by-one bugs here would silently drop or
// include scenarios at the boundary; the deepest-prefix ordering inside the renderer would not catch it.
func TestAnyOverlap(t *testing.T) {
	cases := []struct {
		name               string
		scenStart, scenEnd int
		hunks              []lineRange
		want               bool
	}{
		{"hunk inside scenario", 10, 20, []lineRange{{15, 16}}, true},
		{"scenario inside hunk", 10, 20, []lineRange{{1, 100}}, true},
		{"hunk touches scenario start", 10, 20, []lineRange{{1, 10}}, true},
		{"hunk touches scenario end", 10, 20, []lineRange{{20, 30}}, true},
		{"hunk before scenario, gap", 10, 20, []lineRange{{1, 9}}, false},
		{"hunk after scenario, gap", 10, 20, []lineRange{{21, 30}}, false},
		{"no hunks", 10, 20, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, anyOverlap(tc.scenStart, tc.scenEnd, tc.hunks))
		})
	}
}

// TestParseSpecScenarioRanges covers the scenario-range parser against a synthetic spec.md. The scenarios' Start must point
// to the parent requirement heading (so a SHALL edit upstream of the scenario heading promotes the scenario into the new-
// code set), and End must extend to the line BEFORE the next subheading or EOF.
func TestParseSpecScenarioRanges(t *testing.T) {
	doc := `# Title

## Requirements

### Requirement: First req

The system SHALL do X.

#### Scenario: Alpha

- WHEN x THEN y

#### Scenario: Beta

- WHEN y THEN z

### Requirement: Second req

The system MUST do Y.

#### Scenario: Gamma

- WHEN done
`
	dir := t.TempDir()
	specDir := filepath.Join(dir, "openspec", "specs", "x")
	require.NoError(t, os.MkdirAll(specDir, 0o750))
	path := filepath.Join(specDir, "spec.md")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o644))

	got, err := parseSpecScenarioRanges(path)
	require.NoError(t, err)
	require.Len(t, got, 3)

	// First scenario's Start should be the First-req heading line (line 5), End is the line before the Beta heading
	// (Beta heading is at line 13, so Alpha ends at line 12).
	assert.Equal(t, "x/first-req/alpha", got[0].ID)
	assert.Equal(t, 5, got[0].Start, "scenario range should extend back to the requirement heading")
	assert.Equal(t, 12, got[0].End, "scenario range should end on the line before the next subheading")

	assert.Equal(t, "x/first-req/beta", got[1].ID)
	assert.Equal(t, 5, got[1].Start, "Beta also lives under First req; range starts at the req heading")
	assert.Equal(t, 16, got[1].End, "Beta ends on the line before the Second req heading")

	assert.Equal(t, "x/second-req/gamma", got[2].ID)
	assert.Equal(t, 17, got[2].Start, "Gamma starts at the Second req heading")
}

// TestComputeNewCodeScenarioIDs_RejectsDashBaseRef pins the early-exit when --base-ref would shell out as a git option.
// The function must short-circuit before invoking git so an attacker controlling the flag can't force `git merge-base
// HEAD --help` (which opens a pager and could hang CI) or `--exec=<command>`-style abuses.
func TestComputeNewCodeScenarioIDs_RejectsDashBaseRef(t *testing.T) {
	_, err := computeNewCodeScenarioIDs(context.Background(), "openspec/specs", "-help")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --base-ref")
}

// TestComputeNewCodeScenarioIDs_E2E exercises the full git-diff path against a transient repo. We initialise a repo, commit
// a baseline spec, then add one new requirement+scenario and modify a SHALL line under an existing requirement; the gate
// must surface both the new scenario AND every scenario under the modified requirement (because a SHALL edit promotes the
// entire requirement's scenario set).
func TestComputeNewCodeScenarioIDs_E2E(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "--quiet")
	runGit(t, dir, "config", "user.email", "spectrace@example.test")
	runGit(t, dir, "config", "user.name", "spectrace test")

	specDir := filepath.Join(dir, "openspec", "specs", "alpha")
	require.NoError(t, os.MkdirAll(specDir, 0o750))
	specPath := filepath.Join(specDir, "spec.md")

	baseline := strings.Join([]string{
		"# Alpha",
		"",
		"## Requirements",
		"",
		"### Requirement: Existing req",
		"",
		"The system SHALL do legacy thing.",
		"",
		"#### Scenario: Legacy scenario",
		"",
		"- WHEN x THEN y",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(specPath, []byte(baseline), 0o644))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "--quiet", "-m", "baseline")
	runGit(t, dir, "branch", "base") // baseRef will be `base`

	// Now modify: tighten the SHALL wording (promotes Legacy scenario) AND add a new requirement+scenario at the end.
	modified := strings.Join([]string{
		"# Alpha",
		"",
		"## Requirements",
		"",
		"### Requirement: Existing req",
		"",
		"The system SHALL strictly do legacy thing.",
		"",
		"#### Scenario: Legacy scenario",
		"",
		"- WHEN x THEN y",
		"",
		"### Requirement: New req",
		"",
		"The system MUST do new thing.",
		"",
		"#### Scenario: New scenario",
		"",
		"- WHEN a THEN b",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(specPath, []byte(modified), 0o644))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "--quiet", "-m", "modify + add")

	// Switch into the repo so the git plumbing reads the right working tree. t.Chdir restores the cwd at test end.
	t.Chdir(dir)

	got, err := computeNewCodeScenarioIDs(context.Background(), "openspec/specs", "base")
	require.NoError(t, err)
	assert.Contains(t, got, "alpha/existing-req/legacy-scenario",
		"SHALL edit under Existing req must promote its scenario into new-code scope")
	assert.Contains(t, got, "alpha/new-req/new-scenario",
		"freshly-added scenario must be in new-code scope")
	assert.Len(t, got, 2)
}

// runGit is a small helper that runs git in the test repo and fails fast with the combined output. Tests use this to keep
// the e2e flow readable; production code uses exec.CommandContext directly.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // args are test-local literals
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestValidateBaseRef pins the dash-prefix rejection added in response to Copilot's PR #281 review. The two legitimate-
// looking refs (a branch name, a SHA) must pass; anything starting with `-` must be rejected because git would parse it
// as an option flag. Git itself refuses to create refs starting with `-`, so this check has no false-positive surface.
func TestValidateBaseRef(t *testing.T) {
	cases := []struct {
		name    string
		baseRef string
		wantErr bool
	}{
		{"origin/main passes", "origin/main", false},
		{"branch name passes", "main", false},
		{"sha passes", "abc1234567", false},
		{"leading dash is rejected", "-help", true},
		{"leading double-dash is rejected", "--all", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBaseRef(tc.baseRef)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid --base-ref")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFilterByIDSet covers the small helper that scopes the gate's uncovered set to a subset by ID.
func TestFilterByIDSet(t *testing.T) {
	in := []Scenario{
		{ID: "a/b/c"}, {ID: "d/e/f"}, {ID: "g/h/i"},
	}
	t.Run("empty set drops everything", func(t *testing.T) {
		assert.Empty(t, filterByIDSet(in, map[string]struct{}{}))
	})
	t.Run("partial set keeps only matching ids", func(t *testing.T) {
		got := filterByIDSet(in, map[string]struct{}{"a/b/c": {}, "g/h/i": {}})
		require.Len(t, got, 2)
		assert.Equal(t, "a/b/c", got[0].ID)
		assert.Equal(t, "g/h/i", got[1].ID)
	})
}
