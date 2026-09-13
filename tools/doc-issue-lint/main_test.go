package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInScope(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"README.md":                        true,
		"SECURITY.md":                      true,
		"docker-compose.prod.README.md":    true,
		"docs/operations.md":               true,
		"docs/new-operator-guide.md":       true,
		"docs/api/openapi.yaml":            true,
		"docs/attack-navigator-layer.json": true,
		"server/rules/internal/catalog/pack/suspicious_exec.yml": true,
		"server/rules/internal/catalog/pack/nested/x.yml":        false,
		"server/rules/internal/catalog/suspicious_exec.go":       false,
		"CHANGELOG.md":                      false,
		"CONTRIBUTING.md":                   false,
		"CLAUDE.md":                         false,
		"docs/adr/0010-stateless-server.md": false,
		"docs/maintenance/log.md":           false,
		"docs/release-checklist.md":         false,
		"docs/doc-versioning.md":            false,
		"docs/rules/README.md":              false,
		"docs/api.json":                     false,
		"tools/dash-lint/README.md":         false,
	}
	for p, want := range cases {
		if got := inScope(p); got != want {
			t.Errorf("inScope(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestExtractRefs(t *testing.T) {
	t.Parallel()
	patterns := newRefPatterns(defaultRepo)
	cases := []struct {
		name string
		in   string
		want []int
	}{
		{"bare reference", "Tracked in #862.", []int{862}},
		{"reference at line start", "#12 is open", []int{12}},
		{"parenthesized reference", "is not detected (issue #934)", []int{934}},
		{"several on one line", "#301 and #801, see also (#776)", []int{301, 801, 776}},
		{"qualified reference to this repo", "see getvictor/fleet-edr#518", []int{518}},
		{"issue URL", "[issue #565](https://github.com/getvictor/fleet-edr/issues/565)", []int{565, 565}},
		{"pull request URL", "https://github.com/getvictor/fleet-edr/pull/1023", []int{1023}},
		{"another repository not matched", "fleetdm/fleet#123 and github.com/fleetdm/fleet/issues/9", nil},
		{"hex color not matched", `"color": "#31a354", "bg": "#000000"`, nil},
		{"six digit run not matched", "code #123456", nil},
		{"leading zero not matched", "step #0 and #042", nil},
		{"HTML entity not matched", "it&#39;s", nil},
		{"URL fragment not matched", "mappers.ts#L94 and page/#12", nil},
		{"identifier suffix not matched", "item#5 and v1#2", nil},
		{"markdown anchor not matched", "[see](#detection-rule-tuning)", nil},
		{"digits running into letters not matched", "#12abc", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			refs, err := patterns.extractRefs("x.md", []byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, r := range refs {
				got = append(got, r.number)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("extractRefs(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractRefsReportsLine(t *testing.T) {
	t.Parallel()
	refs, err := newRefPatterns(defaultRepo).extractRefs("docs/a.md", []byte("first\n\nthird mentions #7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].path != "docs/a.md" || refs[0].line != 3 || refs[0].number != 7 {
		t.Fatalf("got %+v, want one ref to #7 at docs/a.md:3", refs)
	}
}

func TestFindings(t *testing.T) {
	t.Parallel()
	states := map[int]item{
		1: {kind: kindIssue, state: "OPEN", title: "open gap"},
		2: {kind: kindIssue, state: "CLOSED", title: "shipped fix"},
		3: {kind: kindPullRequest, state: "MERGED", title: "merged change"},
		4: {kind: kindPullRequest, state: "OPEN", title: "in review"},
	}
	cases := []struct {
		name   string
		number int
		want   string
	}{
		{"open issue passes", 1, ""},
		{"closed issue flagged", 2, `docs/a.md:9: #2 is a closed issue: "shipped fix"`},
		{"merged pull request flagged", 3, `docs/a.md:9: #3 is a pull request (merged): "merged change"`},
		{"open pull request flagged", 4, `docs/a.md:9: #4 is a pull request (open): "in review"`},
		{"missing number flagged", 5, "docs/a.md:9: #5 does not exist in this repository"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := findings([]ref{{path: "docs/a.md", line: 9, number: tc.number}}, states)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %v, want no findings", got)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("got %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestUniqueNumbers(t *testing.T) {
	t.Parallel()
	got := uniqueNumbers([]ref{{number: 9}, {number: 3}, {number: 9}, {number: 3}, {number: 1}})
	if !slices.Equal(got, []int{1, 3, 9}) {
		t.Fatalf("uniqueNumbers = %v, want [1 3 9]", got)
	}
}

// fakeLookup answers from a fixed map and records the numbers it was asked about.
type fakeLookup struct {
	states map[int]item
	err    error
	asked  []int
}

func (f *fakeLookup) lookup(_ context.Context, numbers []int) (map[int]item, error) {
	f.asked = numbers
	return f.states, f.err
}

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/guide.md", "Tracked in #10. Fixed by #11.\n")
	write("docs/adr/0001-x.md", "Decided in #12.\n")

	t.Run("closed reference fails with findings", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeLookup{states: map[int]item{
			10: {kind: kindIssue, state: "OPEN", title: "gap"},
			11: {kind: kindIssue, state: "CLOSED", title: "fix"},
		}}
		var stderr bytes.Buffer
		code := runInDir(t, dir, []string{"docs/guide.md", "docs/adr/0001-x.md", "CHANGELOG.md"}, lookup, &stderr)
		if code != exitFindings {
			t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitFindings, stderr.String())
		}
		if !slices.Equal(lookup.asked, []int{10, 11}) {
			t.Errorf("looked up %v, want [10 11]: the internal ADR must not be scanned", lookup.asked)
		}
		if !strings.Contains(stderr.String(), `docs/guide.md:1: #11 is a closed issue: "fix"`) {
			t.Errorf("stderr missing the finding:\n%s", stderr.String())
		}
	})

	t.Run("only open issues passes", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeLookup{states: map[int]item{
			10: {kind: kindIssue, state: "OPEN"},
			11: {kind: kindIssue, state: "OPEN"},
		}}
		var stderr bytes.Buffer
		if code := runInDir(t, dir, []string{"docs/guide.md"}, lookup, &stderr); code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr.String())
		}
	})

	t.Run("lookup failure is an error, never a pass", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeLookup{err: errors.New("network down")}
		var stderr bytes.Buffer
		if code := runInDir(t, dir, []string{"docs/guide.md"}, lookup, &stderr); code != exitError {
			t.Fatalf("exit %d, want %d", code, exitError)
		}
	})

	t.Run("no references skips the lookup", func(t *testing.T) {
		t.Parallel()
		lookup := &fakeLookup{err: errors.New("must not be called")}
		var stderr bytes.Buffer
		if code := runInDir(t, dir, []string{"docs/adr/0001-x.md", "docs/missing.md"}, lookup, &stderr); code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr.String())
		}
	})
}

// runInDir runs the gate with dir as the repository root, so the fixture paths are repo-relative exactly as git ls-files gives them.
func runInDir(t *testing.T, dir string, paths []string, lookup stateLookup, stderr *bytes.Buffer) int {
	t.Helper()
	return run(t.Context(), os.DirFS(dir), paths, newRefPatterns(defaultRepo), lookup, stderr)
}
