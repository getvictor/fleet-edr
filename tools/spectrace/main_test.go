package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlugify pins the canonical-ID slug rule documented in docs/testing-strategy.md. If this test ever fails, every existing
// canonical ID may shift; reviewers should treat that as a breaking change to the contract, not an implementation tweak.
func TestSlugify(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Authenticated batch event submission", "authenticated-batch-event-submission"},
		{"trailing punctuation", "A valid agent posts a batch.", "a-valid-agent-posts-a-batch"},
		{"runs of non-alnum collapse", "Foo  --  bar", "foo-bar"},
		{"leading and trailing dashes stripped", "  -- Hello -- ", "hello"}, // dash-lint:ignore test input pins the dash-stripping slug rule
		{"digits are preserved", "Server returns 200 or 204", "server-returns-200-or-204"},
		{"apostrophe becomes dash", "Operator's view", "operator-s-view"},
		{"slashes within title become dashes", "GET/POST round trip", "get-post-round-trip"},
		{"empty input", "", ""},
		{"only punctuation", "...---!!!", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, slugify(tc.in))
		})
	}
}

// TestContainsNormativeKeyword guards the SHALL / MUST gate. The matcher is whole-word + uppercase-only (RFC 2119 convention)
// so casual English use of "must" inside prose does not promote a requirement to normative.
func TestContainsNormativeKeyword(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"uppercase SHALL", "The system SHALL include the host token.", true},
		{"uppercase MUST", "The system MUST mark events delivered only after 2xx.", true},
		{"lowercase shall does not count", "Everyone shall be merry.", false},
		{"lowercase must does not count", "Tests must be cheap.", false},
		{"uppercase SHALL inside larger token does not match", "The marshallerSHALLer routine ran.", false},
		{"uppercase MUST as suffix of identifier does not match", "callMUSTfire was invoked.", false},
		{"empty line", "", false},
		{"MUST followed by punctuation matches", "It MUST.", true},
		{"SHALL at end of line matches", "The agent SHALL", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, containsNormativeKeyword(tc.in))
		})
	}
}

// TestParseSpec_HappyPath covers the document shape used across openspec/specs: one Requirement with a SHALL/MUST body and
// two child Scenarios should produce two normative scenarios with the correctly computed canonical IDs.
func TestParseSpec_HappyPath(t *testing.T) {
	doc := `# Title

## Purpose

text

## Requirements

### Requirement: Authenticated batch event submission

The system SHALL accept batches.

#### Scenario: A valid agent posts a batch

- GIVEN a valid token
- WHEN the agent POSTs
- THEN 200

#### Scenario: An expired token is rejected

- GIVEN an expired token
- WHEN the agent POSTs
- THEN 401
`
	got, err := parseSpec(strings.NewReader(doc), "server-event-ingestion",
		"openspec/specs/server-event-ingestion/spec.md")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t,
		"server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch",
		got[0].ID)
	assert.True(t, got[0].Normative)
	assert.Equal(t,
		"server-event-ingestion/authenticated-batch-event-submission/an-expired-token-is-rejected",
		got[1].ID)
	assert.True(t, got[1].Normative)
}

// TestParseSpec_RequirementWithoutNormative pins the "advisory" classification: a Requirement whose body uses neither SHALL
// nor MUST should still produce scenarios but with Normative=false so the strict gate does not fail on them.
func TestParseSpec_RequirementWithoutNormative(t *testing.T) {
	doc := `### Requirement: Operator may inspect the catalog

The catalog is browsable from the admin UI; this is convenient for operators.

#### Scenario: Operator opens the rules page
`
	got, err := parseSpec(strings.NewReader(doc), "server-detection-rules-engine",
		"openspec/specs/server-detection-rules-engine/spec.md")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.False(t, got[0].Normative,
		"requirement body has no SHALL/MUST, so scenarios under it are advisory")
}

// TestParseSpec_HeadingClosesRequirement ensures that a sibling top-level heading (`## Requirements` or `### Other`) closes
// the active requirement so subsequent scenarios are not falsely attributed to the prior requirement.
func TestParseSpec_HeadingClosesRequirement(t *testing.T) {
	doc := `### Requirement: First

The system SHALL do X.

#### Scenario: One

### Requirement: Second

The system MUST do Y.

#### Scenario: Two
`
	got, err := parseSpec(strings.NewReader(doc), "x", "x/spec.md")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "x/first/one", got[0].ID)
	assert.Equal(t, "x/second/two", got[1].ID)
}

// TestScanFile covers every marker dialect (Go subtest, Go comment, Playwright title, Swift XCTest, malformed-marker
// validation surface, Swift unknown-identifier, Swift ambiguity) in a single table-driven shape per CLAUDE.md's test policy.
// Each case documents what dialect / failure surface it exercises so a future contributor adding a sixth dialect adds one
// row rather than a sixth function.
func TestScanFile(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		path        string
		isSwift     bool
		canonical   map[string]struct{}
		wantMarkers []string // emitted Marker.ID values, in order
	}{
		{
			name: "go subtest name",
			src: `package x
func TestFoo(t *testing.T) {
	t.Run("spec:server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch", func(t *testing.T) {})
}
`,
			path: "x.go", isSwift: false,
			canonical: map[string]struct{}{
				"server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch": {},
			},
			wantMarkers: []string{
				"server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch",
			},
		},
		{
			name: "go comment marker",
			src: `package x
// spec:agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token
func TestUpload(t *testing.T) {}
`,
			path: "x.go", isSwift: false,
			canonical: map[string]struct{}{
				"agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token": {},
			},
			wantMarkers: []string{"agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token"},
		},
		{
			name: "playwright title prefix",
			src: `import { test } from "@playwright/test";
test("spec:ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token renders dashboard", async () => {});
`,
			path: "x.ts", isSwift: false,
			canonical: map[string]struct{}{
				"ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token": {},
			},
			wantMarkers: []string{"ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token"},
		},
		{
			name: "swift xctest identifier",
			src: `class EventSerializerTests: XCTestCase {
    func test_spec_extension_xpc_server_peer_validation_signing_required() throws {}
}
`,
			path: "x.swift", isSwift: true,
			canonical: map[string]struct{}{
				"extension-xpc-server/peer-validation/signing-required": {},
			},
			wantMarkers: []string{"extension-xpc-server/peer-validation/signing-required"},
		},
		{
			name: "malformed marker reaches downstream invalid-ref bucket",
			src: `// spec:Wrong-Case/foo/bar
func Foo() {}
`,
			path: "x.go", isSwift: false,
			canonical:   map[string]struct{}{},
			wantMarkers: []string{"Wrong-Case/foo/bar"}, // captured, validated invalid downstream
		},
		{
			name: "go invalid reference is captured for downstream validation",
			src: `// spec:does-not/exist/at-all
func Foo() {}
`,
			path: "x.go", isSwift: false,
			canonical:   map[string]struct{}{},
			wantMarkers: []string{"does-not/exist/at-all"},
		},
		{
			name: "swift unknown identifier surfaces as swift:<body>",
			src: `class X: XCTestCase {
    func test_spec_does_not_exist() throws {}
}
`,
			path: "x.swift", isSwift: true,
			canonical:   map[string]struct{}{},
			wantMarkers: []string{"swift:does_not_exist"},
		},
		{
			name: "yaml workflow step marker (hash comment)",
			src: `jobs:
  build:
    steps:
      # spec:release-packaging/dry-run-build-on-any-macos-runner/pull-request-runs-the-dry-run
      - name: pkg dry-run
        run: packaging/pkg/build.sh --dry-run
`,
			path: ".github/workflows/pkg-dryrun.yml", isSwift: false,
			canonical: map[string]struct{}{
				"release-packaging/dry-run-build-on-any-macos-runner/pull-request-runs-the-dry-run": {},
			},
			wantMarkers: []string{
				"release-packaging/dry-run-build-on-any-macos-runner/pull-request-runs-the-dry-run",
			},
		},
		{
			name: "shell script marker (hash comment)",
			src: `#!/bin/bash
# spec:release-packaging/uninstall-path-is-deliverable/operator-runs-the-uninstall-script
set -euo pipefail
echo "uninstalling..."
`,
			path: "packaging/pkg/uninstall.sh", isSwift: false,
			canonical: map[string]struct{}{
				"release-packaging/uninstall-path-is-deliverable/operator-runs-the-uninstall-script": {},
			},
			wantMarkers: []string{
				"release-packaging/uninstall-path-is-deliverable/operator-runs-the-uninstall-script",
			},
		},
		{
			name: "yaml workflow multiple markers stacked on one step",
			src: `jobs:
  release:
    steps:
      # spec:release-packaging/real-release-build-is-gated-to-release-tag-refs/tag-push-triggers-a-real-build
      # spec:release-packaging/notarization-and-stapling/released-package-is-stapled
      - name: release pkg
        run: packaging/pkg/build.sh --notarize --staple
`,
			path: ".github/workflows/release.yml", isSwift: false,
			canonical: map[string]struct{}{
				"release-packaging/real-release-build-is-gated-to-release-tag-refs/tag-push-triggers-a-real-build": {},
				"release-packaging/notarization-and-stapling/released-package-is-stapled":                          {},
			},
			wantMarkers: []string{
				"release-packaging/real-release-build-is-gated-to-release-tag-refs/tag-push-triggers-a-real-build",
				"release-packaging/notarization-and-stapling/released-package-is-stapled",
			},
		},
		{
			name: "yaml inline trailing-comment marker (hash after step text)",
			src: `jobs:
  build:
    steps:
      - run: ./build.sh # spec:release-packaging/final-artifact-naming/versioned-package-name
`,
			path: ".github/workflows/release.yml", isSwift: false,
			canonical: map[string]struct{}{
				"release-packaging/final-artifact-naming/versioned-package-name": {},
			},
			wantMarkers: []string{
				"release-packaging/final-artifact-naming/versioned-package-name",
			},
		},
		{
			// Two canonical IDs collapse to the same Swift identifier (`foo-bar` vs `foo/bar`). resolveSwiftMarker must NOT
			// pick one at random; it surfaces a `swift-ambiguous:` reference so check reports it as invalid and the
			// contributor renames one of the conflicting headings.
			name: "swift ambiguous identifier surfaces as swift-ambiguous:<body>",
			src: `class X: XCTestCase {
    func test_spec_foo_bar() throws {}
}
`,
			path: "x.swift", isSwift: true,
			canonical: map[string]struct{}{
				"foo-bar":   {}, // 2-segment, doesn't matter that this isn't a real canonical ID for this unit test
				"foo/bar":   {},
				"unrelated": {},
			},
			wantMarkers: []string{"swift-ambiguous:foo_bar"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swiftIndex := buildSwiftIndex(tc.canonical)
			got, err := scanFile(strings.NewReader(tc.src), tc.path, tc.isSwift, tc.canonical, swiftIndex)
			require.NoError(t, err)
			require.Len(t, got, len(tc.wantMarkers))
			for i, want := range tc.wantMarkers {
				assert.Equal(t, want, got[i].ID, "marker %d", i)
				assert.Equal(t, tc.path, got[i].SourcePath, "marker %d source path", i)
			}
		})
	}
}

// TestSwiftFormOf pins the canonical-to-Swift dialect translation. Slashes AND dashes both map to underscores.
func TestSwiftFormOf(t *testing.T) {
	assert.Equal(t, "extension_xpc_server_peer_validation_signing_required",
		swiftFormOf("extension-xpc-server/peer-validation/signing-required"))
}

// TestBuildCanonicalSet_DuplicateIDsAreRejected pins the duplicate-detection contract added in this PR. If two scenarios
// slug to the same canonical ID, buildCanonicalSet must fail fast with both source locations rather than silently
// collapsing them into a single map entry.
func TestBuildCanonicalSet_DuplicateIDsAreRejected(t *testing.T) {
	scenarios := []Scenario{
		{ID: "x/foo-bar/baz", SourcePath: "openspec/specs/x/spec.md", SourceLine: 10},
		{ID: "y/qux/quux", SourcePath: "openspec/specs/y/spec.md", SourceLine: 20},
		{ID: "x/foo-bar/baz", SourcePath: "openspec/specs/x/spec.md", SourceLine: 30},
	}
	_, err := buildCanonicalSet(scenarios)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate canonical scenario ID")
	assert.Contains(t, err.Error(), "openspec/specs/x/spec.md:10")
	assert.Contains(t, err.Error(), "openspec/specs/x/spec.md:30")
}

// TestBuildCanonicalSet_NoDuplicatesIsClean confirms the happy path: distinct IDs produce a populated set with no error.
func TestBuildCanonicalSet_NoDuplicatesIsClean(t *testing.T) {
	scenarios := []Scenario{
		{ID: "a/b/c"}, {ID: "d/e/f"},
	}
	set, err := buildCanonicalSet(scenarios)
	require.NoError(t, err)
	assert.Len(t, set, 2)
}
