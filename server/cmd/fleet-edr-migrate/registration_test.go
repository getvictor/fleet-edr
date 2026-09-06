package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contextsWithMigrations reads the bounded contexts that ship migrations from the TREE rather than from a list.
//
// Driven from the filesystem deliberately. A hardcoded expectation here would be the same defect one level up: a context added
// without an entry would also be missing from the expectation, and the test would agree with the bug.
func contextsWithMigrations(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("../..")
	require.NoError(t, err, "the server tree must be readable from this package")

	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sqls, err := filepath.Glob(filepath.Join("../..", e.Name(), "migrations", "*.sql"))
		require.NoError(t, err)
		if len(sqls) > 0 {
			found = append(found, e.Name())
		}
	}
	require.NotEmpty(t, found, "no context migrations were found, so this test would prove nothing")
	sort.Strings(found)
	return found
}

// spec:server-availability/schema-is-managed-by-versioned-forward-only-per-context-migrations/a-context-shipping-migrations-is-registered
//
// TestEveryContextWithMigrationsIsRegistered is the gate issue #849 asks for, and the failure it catches is silent by nature.
//
// Registering a bounded context takes entries in several independent lists, and every one of them is a slice literal consumed
// elsewhere: omitting an entry breaks no build and fails no test, it just makes something quietly do less. This CLI exiting 0
// having applied seven of eight contexts is exactly that shape, and it is what happened to observability.
//
// The consequences are not cosmetic. A deployment that migrates as a privileged step and then runs the app without DDL grants
// fails at boot on the unregistered context, and a multi-replica boot has every replica racing goose for it, which is the race
// this CLI exists to remove.
func TestEveryContextWithMigrationsIsRegistered(t *testing.T) {
	t.Parallel()

	registered := make(map[string]struct{})
	for _, m := range migrations() {
		registered[m.context] = struct{}{}
	}

	for _, ctxName := range contextsWithMigrations(t) {
		assert.Contains(t, registered, ctxName,
			"%s ships migrations but is not registered with the standalone migrator, which would exit 0 having skipped it", ctxName)
	}
}

// spec:server-availability/schema-is-managed-by-versioned-forward-only-per-context-migrations/a-registered-context-ships-migrations
//
// TestNoRegisteredContextIsMissingItsMigrations is the other direction, and it guards a subtler mistake: a registered context
// whose migrations directory was renamed or removed. Its ApplySchema would then be a no-op that reports success, so the CLI would
// again exit 0 having done less than its name says.
func TestNoRegisteredContextIsMissingItsMigrations(t *testing.T) {
	t.Parallel()

	onDisk := make(map[string]struct{})
	for _, name := range contextsWithMigrations(t) {
		onDisk[name] = struct{}{}
	}

	for _, m := range migrations() {
		assert.Contains(t, onDisk, m.context,
			"%s is registered with the migrator but ships no migrations, so its schema step does nothing", m.context)
	}
}
