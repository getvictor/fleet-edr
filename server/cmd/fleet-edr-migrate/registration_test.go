package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/contexts"
)

// shippingMigrations is the shared tree scan, wrapped for the assertions below.
//
// One definition across both guards, because two copies of the rule that decides which contexts count can disagree, and then the
// two gates would police different sets: the defect they exist to catch, one level up. Review caught the duplication.
func shippingMigrations(t *testing.T) []string {
	t.Helper()
	found, err := contexts.MySQLMigrations("../..")
	require.NoError(t, err, "the server tree must be readable from this package")
	require.NotEmpty(t, found, "no context migrations were found, so this test would prove nothing")
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

	for _, ctxName := range shippingMigrations(t) {
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
	for _, name := range shippingMigrations(t) {
		onDisk[name] = struct{}{}
	}

	for _, m := range migrations() {
		assert.Contains(t, onDisk, m.context,
			"%s is registered with the migrator but ships no migrations, so its schema step does nothing", m.context)
	}
}
