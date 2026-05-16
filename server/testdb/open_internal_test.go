package testdb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSanitizeDBName_Properties pins the four properties Open() relies on:
//
//  1. Distinct testNames produce distinct DB names (after every replacement). The naive replacer collapses `/` and `.` into
//     `_`, so without the testName-derived hash these would collide.
//  2. Backticks are replaced — without this, a Go test name containing one would break the CREATE DATABASE DDL.
//  3. The DB name fits MySQL's 64-char identifier ceiling.
//  4. Per-process salt + testName hash are present, so cross-process and within-process collisions are both bounded.
func TestSanitizeDBName_Properties(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		testName string
	}{
		{"plain", "TestExample"},
		{"slash separator", "TestParent/Child"},
		{"dot separator", "TestParent.Child"},
		{"backtick injection attempt", "Test`drop"},
		{"space", "Test Example"},
		{"hyphen", "Test-Example"},
		{"very long name that overflows the 64-char ceiling and needs truncation", "TestVeryLongName/" + strings.Repeat("subtest_path_segment_", 5)},
	}

	seen := make(map[string]string)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeDBName(tc.testName)

			// (3) Always under MySQL's identifier ceiling.
			assert.LessOrEqual(t, len(got), 64, "dbName must fit MySQL's 64-char identifier ceiling")

			// (2) Backticks must not survive into the DB name; they would break the DDL string in Open().
			assert.NotContains(t, got, "`", "backticks must be replaced — they would break CREATE DATABASE `name`")

			// (4) The per-process salt is always present so cross-process tests with the same name don't collide.
			assert.Contains(t, got, processSalt, "per-process salt must be embedded for cross-process uniqueness")
		})
	}

	// (1) Distinct testNames must produce distinct DB names. Walked outside the t.Run loop so the check sees every output.
	for _, tc := range cases {
		got := sanitizeDBName(tc.testName)
		if prior, dup := seen[got]; dup {
			t.Errorf("collision: testNames %q and %q both produced %q", prior, tc.testName, got)
		}
		seen[got] = tc.testName
	}
}

// TestSanitizeDBName_CollisionRegressions pins the specific replacement-collapse patterns that previously broke parallel
// subtests: a parent with a / separator vs the same name with a . separator, both of which the replacer rewrites to _.
// Without a hash of the original testName the two would map to the same DB.
func TestSanitizeDBName_CollisionRegressions(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"TestX/A", "TestX.A"},
		{"TestX/A", "TestX-A"},
		{"TestX/A", "TestX A"},
		{"TestX/A", "TestX`A"},
	}
	for _, p := range pairs {
		assert.NotEqualf(t, sanitizeDBName(p[0]), sanitizeDBName(p[1]),
			"sanitizeDBName(%q) must not collide with sanitizeDBName(%q)", p[0], p[1])
	}
}

// TestSanitizeDBName_Idempotent: identical testName produces identical DB name across calls. Without this the per-test
// DROP+CREATE+DROP-on-cleanup sequence in Open() would race itself.
func TestSanitizeDBName_Idempotent(t *testing.T) {
	t.Parallel()
	a := sanitizeDBName("TestRepeatable")
	b := sanitizeDBName("TestRepeatable")
	assert.Equal(t, a, b)
}

// TestStripDBName_RejectsMalformed: a malformed DSN must surface a parse error rather than silently strip nothing and let
// the caller run DDL against the wrong database. Pinning the error case keeps the failure mode of Open() loud.
func TestStripDBName_RejectsMalformed(t *testing.T) {
	t.Parallel()

	_, err := stripDBName("not-a-real-dsn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse DSN")
}

// TestStripDBName_RoundTrip: a valid DSN comes back with the DBName field cleared. Used by Open() to obtain the admin
// connection string that any subsequent CREATE DATABASE applies to.
func TestStripDBName_RoundTrip(t *testing.T) {
	t.Parallel()
	out, err := stripDBName("user:pass@tcp(127.0.0.1:3306)/some_db?parseTime=true")
	require.NoError(t, err)
	assert.NotContains(t, out, "some_db", "stripDBName must clear the DBName field")
	assert.Contains(t, out, "127.0.0.1:3306", "host:port must survive the round-trip")
}

// TestReplaceDBName_RejectsMalformed mirrors TestStripDBName_RejectsMalformed for the other DSN helper. Both feed Open()'s
// per-test DSN and both must fail loudly on a parse miss instead of silently corrupting the per-test isolation guarantee.
func TestReplaceDBName_RejectsMalformed(t *testing.T) {
	t.Parallel()

	_, err := replaceDBName("not-a-real-dsn", "new_db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse DSN")
}

// TestReplaceDBName_RoundTrip: substitutes the DBName cleanly when the DSN parses.
func TestReplaceDBName_RoundTrip(t *testing.T) {
	t.Parallel()
	out, err := replaceDBName("user:pass@tcp(127.0.0.1:3306)/original_db?parseTime=true", "renamed_db")
	require.NoError(t, err)
	assert.Contains(t, out, "renamed_db")
	assert.NotContains(t, out, "original_db")
}
