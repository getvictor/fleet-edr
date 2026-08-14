//go:build integration

package tests

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/testdb"
)

// isCHIdentifierRune reports whether a single rune is legal in an unquoted ClickHouse identifier. It mirrors the character filter
// safeDBName applies, so the tests below check the output against the same alphabet the builder claims to emit.
func isCHIdentifierRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
}

// saltedPrefix is the exact, delimiter-bounded head every generated name must carry: the literal prefix, this process's salt, and
// the separator. The assertions below check this whole prefix rather than merely that the salt appears somewhere, so they pin the
// salt's POSITION: a refactor that moved the salt into the readable segment, or dropped it while the sanitized test name happened
// to contain those bytes, still fails. Containment alone would pass in both cases.
func saltedPrefix() string { return "edr_test_" + testdb.ProcessSalt() + "_" }

// isValidCHIdentifier reports whether every rune is legal in an UNQUOTED ClickHouse identifier. The provisioning DDL in
// openTestArchiveWithHandle interpolates the name without quoting, so this is load-bearing rather than cosmetic.
func isValidCHIdentifier(s string) bool {
	for _, r := range s {
		if !isCHIdentifierRune(r) {
			return false
		}
	}
	return true
}

// TestSafeDBName_Properties pins the properties openTestArchiveWithHandle's DROP-then-CREATE sequence relies on, on the specific
// shapes that have caused real breakage. It mirrors TestSanitizeDBName_Properties in server/testdb for the ClickHouse side. These
// stay example-based on purpose: the separator and injection rows are the auditable record of what went wrong, which is exactly
// the case CLAUDE.md says PBT should not replace. TestSafeDBName_PBT generalises the same invariants over arbitrary input.
func TestSafeDBName_Properties(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		testName string
	}{
		{"plain", "TestEventArchive"},
		{"slash separator", "TestEventArchive/NetworkEvents"},
		{"dot separator", "TestEventArchive.NetworkEvents"},
		{"space", "TestEventArchive NetworkEvents"},
		{"hyphen", "TestEventArchive-NetworkEvents"},
		{"backtick injection attempt", "TestEventArchive`drop"},
		{"quote injection attempt", "TestEventArchive'; DROP DATABASE edr; --"},
		{"uppercase is folded", "TESTEVENTARCHIVE"},
		{"overlong name is truncated", "TestEventArchive/" + strings.Repeat("subtest_path_segment_", 20)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := safeDBName(tc.testName)

			assert.Truef(t, isValidCHIdentifier(got),
				"safeDBName(%q) = %q must be a valid unquoted identifier", tc.testName, got)
			assert.LessOrEqualf(t, len(got), maxClickHouseDBNameLen,
				"safeDBName(%q) = %d bytes, over ClickHouse's %d-byte ceiling", tc.testName, len(got), maxClickHouseDBNameLen)
			assert.Truef(t, strings.HasPrefix(got, saltedPrefix()),
				"safeDBName(%q) = %q must open with %q so the salt keeps its position", tc.testName, got, saltedPrefix())
		})
	}
}

// TestSafeDBName_CollisionRegressions pins the separator pairs the character loop folds onto one another. The per-process salt
// does not help here: both names collide WITHIN a process, so only the hash of the original name keeps them apart. Without it,
// two parallel subtests of one parent provision the same database and the first to finish drops it under the second.
func TestSafeDBName_CollisionRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		left  string
		right string
	}{
		{"slash vs dot", "TestX/A", "TestX.A"},
		{"slash vs hyphen", "TestX/A", "TestX-A"},
		{"slash vs space", "TestX/A", "TestX A"},
		{"slash vs backtick", "TestX/A", "TestX`A"},
		{"case only", "TestX/A", "TestX/a"},
		// Two overlong names sharing a truncated prefix: the readable segment is identical after truncation, so only the
		// hash (taken over the FULL original name) separates them.
		{
			"overlong shared prefix",
			"TestX/" + strings.Repeat("z", 300) + "left",
			"TestX/" + strings.Repeat("z", 300) + "right",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.NotEqualf(t, safeDBName(tc.left), safeDBName(tc.right),
				"safeDBName(%q) must not collide with safeDBName(%q)", tc.left, tc.right)
		})
	}
}

// TestSafeDBName_Idempotent: the same test name must map to the same database across calls, because openTestArchiveWithHandle
// derives the name once for CREATE and again in t.Cleanup for DROP. A non-deterministic name would leak every test database.
func TestSafeDBName_Idempotent(t *testing.T) {
	t.Parallel()

	first := safeDBName("TestRepeatable")
	assert.Equal(t, first, safeDBName("TestRepeatable"))
	// The bare literal, deliberately, not saltedPrefix(): a cleanup script sweeping leftovers from an earlier, already-exited
	// process cannot know that process's salt, so "edr_test_" is the only stable handle it can match on.
	assert.True(t, strings.HasPrefix(first, "edr_test_"), "prefix must stay stable: cleanup scripts key off it")
}

// TestSafeDBName_PBT generalises the invariants above across an input space no table can enumerate. A Go test name is a nearly
// arbitrary string (subtests interpolate fixture data, and rapid's own generated names land here verbatim), so the identifier
// and length guarantees have to hold for all of them, not just the shapes we thought to list.
//
// Properties: for any input, the output is a valid unquoted ClickHouse identifier, fits the measured 247-byte ceiling, carries
// the per-process salt, keeps the edr_test_ prefix, and is deterministic.
func TestSafeDBName_PBT(t *testing.T) {
	t.Parallel()

	// A vacuous Contains check would pass if the salt were ever empty, so assert it is not, once, up front.
	require.NotEmpty(t, testdb.ProcessSalt(), "process salt must be non-empty")

	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.String().Draw(rt, "testName")
		got := safeDBName(name)

		require.Truef(rt, isValidCHIdentifier(got),
			"safeDBName(%q) = %q is not a valid unquoted identifier", name, got)
		require.LessOrEqualf(rt, len(got), maxClickHouseDBNameLen,
			"safeDBName(%q) = %d bytes, over the %d-byte ceiling", name, len(got), maxClickHouseDBNameLen)
		require.Truef(rt, strings.HasPrefix(got, saltedPrefix()),
			"safeDBName(%q) = %q must open with %q; truncation must never reach the salt", name, got, saltedPrefix())
		require.Equalf(rt, got, safeDBName(name), "safeDBName(%q) is not deterministic", name)
	})
}
