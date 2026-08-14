//go:build integration

package tests

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/testdb"
)

// TestSafeDBName_Properties pins the three properties openTestArchiveWithHandle's DROP-then-CREATE sequence relies on. It mirrors
// TestSanitizeDBName_Properties in server/testdb for the ClickHouse side, where the DDL interpolates the name UNQUOTED, so the
// charset rule is load-bearing rather than cosmetic.
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := safeDBName(tc.testName)

			// Valid unquoted ClickHouse identifier: the DDL does not backtick-quote, so anything outside [a-z0-9_] would
			// either break the statement or, for the quote case above, smuggle a second one in.
			for _, r := range got {
				assert.Truef(t, (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_',
					"safeDBName(%q) = %q contains %q, which is not a valid unquoted identifier rune", tc.testName, got, r)
			}

			// The per-process salt keeps two concurrent `go test` processes from dropping each other's live database.
			assert.Contains(t, got, testdb.ProcessSalt(), "per-process salt must be embedded for cross-process uniqueness")
		})
	}
}

// TestSafeDBName_CollisionRegressions pins the separator pairs the character loop folds onto one another. The per-process salt
// does not help here: both names collide WITHIN a process, so only the hash of the original name keeps them apart. Without it,
// two parallel subtests of one parent provision the same database and the first to finish drops it under the second.
func TestSafeDBName_CollisionRegressions(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"TestX/A", "TestX.A"},
		{"TestX/A", "TestX-A"},
		{"TestX/A", "TestX A"},
		{"TestX/A", "TestX`A"},
		{"TestX/A", "TestX/a"},
	}
	for _, p := range pairs {
		assert.NotEqualf(t, safeDBName(p[0]), safeDBName(p[1]),
			"safeDBName(%q) must not collide with safeDBName(%q)", p[0], p[1])
	}
}

// TestSafeDBName_Idempotent: the same test name must map to the same database across calls, because openTestArchiveWithHandle
// derives the name once for CREATE and again in t.Cleanup for DROP. A non-deterministic name would leak every test database.
func TestSafeDBName_Idempotent(t *testing.T) {
	t.Parallel()

	first := safeDBName("TestRepeatable")
	assert.Equal(t, first, safeDBName("TestRepeatable"))
	assert.True(t, strings.HasPrefix(first, "edr_test_"), "prefix must stay stable: cleanup scripts key off it")
}
