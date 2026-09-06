package full

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contextsWithMigrations reads the bounded contexts that ship migrations from the TREE rather than from a list, for the reason
// the migrator's copy of this does: a hardcoded expectation would be the same defect one level up, agreeing with the bug.
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

// TestFixtureAppliesEveryContextsSchema is the second half of the gate issue #849 asks for.
//
// This fixture promises "every context's schema", and a context missing from it produces a database without the tables it
// claims. The symptom is not a failure but a workaround: a test that needs those tables hand-applies the schema, which then
// looks like ordinary setup rather than a gap. Two of the four registration lists were missed adding rulecontent in #847, this
// one among them, and review caught both rather than a gate.
func TestFixtureAppliesEveryContextsSchema(t *testing.T) {
	t.Parallel()

	applied := make(map[string]struct{})
	for _, step := range schemaSteps() {
		applied[step.name] = struct{}{}
	}

	for _, ctxName := range contextsWithMigrations(t) {
		assert.Contains(t, applied, ctxName,
			"%s ships migrations but this fixture does not apply its schema, so tests needing those tables hand-apply it", ctxName)
	}
}

// TestFixtureAppliesNothingWithoutMigrations is the other direction: a step for a context whose migrations have been renamed or
// removed applies nothing and reports success, so the fixture would silently stop delivering tables it still names.
func TestFixtureAppliesNothingWithoutMigrations(t *testing.T) {
	t.Parallel()

	onDisk := make(map[string]struct{})
	for _, name := range contextsWithMigrations(t) {
		onDisk[name] = struct{}{}
	}

	for _, step := range schemaSteps() {
		assert.Contains(t, onDisk, step.name,
			"%s is applied by this fixture but ships no migrations, so the step does nothing", step.name)
	}
}
