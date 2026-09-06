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
