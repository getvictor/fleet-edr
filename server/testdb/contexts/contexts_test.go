package contexts_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/contexts"
)

// TestMySQLMigrations_FindsOnlyDirectoriesHoldingMigrations pins what "a context that ships migrations" means, which is the rule
// both registration guards police. Getting it wrong makes both of them police the wrong set, silently.
func TestMySQLMigrations_FindsOnlyDirectoriesHoldingMigrations(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	// Two contexts that ship migrations, deliberately created out of alphabetical order.
	for _, name := range []string{"zulu", "alpha"} {
		dir := filepath.Join(root, name, "migrations")
		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "00001_init.sql"), []byte("-- +goose Up\n"), 0o600))
	}
	// A context with a migrations directory but nothing in it. It ships no migrations, so a guard demanding it be registered
	// would demand a step that does nothing.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty", "migrations"), 0o750))
	// A context with no migrations directory at all: the ordinary shape of one that owns no tables.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "tableless", "internal"), 0o750))
	// A stray file at the top level, which a directory-only walk must not mistake for a context.
	require.NoError(t, os.WriteFile(filepath.Join(root, "doc.go"), []byte("package server\n"), 0o600))

	found, err := contexts.MySQLMigrations(root)
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "zulu"}, found,
		"only directories holding migration files count, and the result is sorted so both guards see one order")
}

// TestMySQLMigrations_ReportsAnUnreadableRoot keeps a broken scan from reading as "no contexts ship migrations", which would make
// both guards vacuously pass at the moment they are most needed.
func TestMySQLMigrations_ReportsAnUnreadableRoot(t *testing.T) {
	t.Parallel()
	_, err := contexts.MySQLMigrations(filepath.Join(t.TempDir(), "no-such-directory"))
	require.Error(t, err)
}

// TestMySQLMigrations_HandlesAPathWithGlobMetacharacters is the defect review caught, and it is the worst kind for a guard: the
// scan reports nothing, both registration gates then have nothing to check, and they pass at exactly the moment they matter.
//
// A checkout under a path containing brackets is unusual but legal, and the old glob-based scan returned zero matches and a nil
// error for it. Measured before the fix, not assumed.
func TestMySQLMigrations_HandlesAPathWithGlobMetacharacters(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "checkout[1]")
	dir := filepath.Join(root, "alpha", "migrations")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "00001_init.sql"), []byte("-- +goose Up\n"), 0o600))

	found, err := contexts.MySQLMigrations(root)
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha"}, found,
		"a path with glob metacharacters must not make a context look like it ships no migrations")
}

// TestMySQLMigrations_ReportsAnUnreadableMigrationsDirectory keeps an access failure from reading as "this context ships
// nothing", for the same reason: a guard that cannot see the tree must fail rather than agree.
func TestMySQLMigrations_ReportsAnUnreadableMigrationsDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "alpha", "migrations")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "00001_init.sql"), []byte("-- +goose Up\n"), 0o600))
	require.NoError(t, os.Chmod(dir, 0o000))
	// Restored so t.TempDir's own cleanup can remove the tree. gosec reads any chmod above 0600 as a finding, and a directory
	// needs its execute bit to be traversable, so the exemption is narrowed to this line rather than the file.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory must be traversable for cleanup to remove it

	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("this filesystem or user can read a 0000 directory, so the failure cannot be provoked here")
	}
	_, err := contexts.MySQLMigrations(root)
	require.Error(t, err, "an unreadable migrations directory must fail the scan rather than empty it")
}
