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
		{"leading and trailing dashes stripped", "  -- Hello -- ", "hello"},
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
		{"SHALL substring inside word does not match", "He marshalled the data.", false},
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

// TestScanFile_GoSubtest exercises the Go subtest-name marker form: `t.Run("spec:<id>", ...)`. The marker should resolve to
// the canonical (slashed) ID regardless of surrounding quoting.
func TestScanFile_GoSubtest(t *testing.T) {
	src := `package x
func TestFoo(t *testing.T) {
	t.Run("spec:server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch", func(t *testing.T) {})
}
`
	canonical := map[string]struct{}{
		"server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch": {},
	}
	got, err := scanFile(strings.NewReader(src), "x.go", false, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch", got[0].ID)
}

// TestScanFile_GoComment covers the `// spec:<id>` comment form used when the t.Run name should stay short.
func TestScanFile_GoComment(t *testing.T) {
	src := `package x
// spec:agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token
func TestUpload(t *testing.T) {}
`
	canonical := map[string]struct{}{
		"agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token": {},
	}
	got, err := scanFile(strings.NewReader(src), "x.go", false, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// TestScanFile_PlaywrightTitlePrefix covers `test("spec:<id> <name>", ...)` in TypeScript Playwright suites.
func TestScanFile_PlaywrightTitlePrefix(t *testing.T) {
	src := `import { test } from "@playwright/test";
test("spec:ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token renders dashboard", async () => {});
`
	canonical := map[string]struct{}{
		"ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token": {},
	}
	got, err := scanFile(strings.NewReader(src), "x.ts", false, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token", got[0].ID)
}

// TestScanFile_SwiftXCTest covers the underscored Swift identifier form. Underscores in the source are ambiguously dashes or
// slashes per the docs/testing-strategy.md mapping; resolveSwift disambiguates against the known canonical-ID set.
func TestScanFile_SwiftXCTest(t *testing.T) {
	src := `class EventSerializerTests: XCTestCase {
    func test_spec_extension_xpc_server_peer_validation_signing_required() throws {}
}
`
	canonical := map[string]struct{}{
		"extension-xpc-server/peer-validation/signing-required": {},
	}
	got, err := scanFile(strings.NewReader(src), "x.swift", true, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "extension-xpc-server/peer-validation/signing-required", got[0].ID,
		"resolveSwift must collapse the dialect difference back to the canonical slashed form")
}

// TestScanFile_InvalidReferenceIsFlagged ensures that a marker pointing to a non-existent ID is captured (not silently
// dropped) so the check pass can fail the build on stale references after a spec rename.
func TestScanFile_InvalidReferenceIsFlagged(t *testing.T) {
	src := `// spec:does-not/exist/at-all
func Foo() {}
`
	canonical := map[string]struct{}{} // empty: no valid IDs
	got, err := scanFile(strings.NewReader(src), "x.go", false, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "does-not/exist/at-all", got[0].ID)
}

// TestScanFile_SwiftUnknownIdentifierFlagged ensures that a `test_spec_foo` identifier that does not resolve to any canonical
// ID is reported with a `swift:` prefix instead of being silently dropped, so check can flag it as an invalid reference.
func TestScanFile_SwiftUnknownIdentifierFlagged(t *testing.T) {
	src := `class X: XCTestCase {
    func test_spec_does_not_exist() throws {}
}
`
	canonical := map[string]struct{}{} // empty
	got, err := scanFile(strings.NewReader(src), "x.swift", true, canonical)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "swift:does_not_exist", got[0].ID)
}

// TestSwiftFormOf pins the canonical-to-Swift dialect translation. Slashes AND dashes both map to underscores.
func TestSwiftFormOf(t *testing.T) {
	assert.Equal(t, "extension_xpc_server_peer_validation_signing_required",
		swiftFormOf("extension-xpc-server/peer-validation/signing-required"))
}
