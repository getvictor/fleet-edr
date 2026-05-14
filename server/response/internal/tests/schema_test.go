//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestSchema_TenantIDOnCommands locks in the wave-1 tenant-scaffolding
// migration: response's `commands` table gains a tenant_id VARCHAR(64)
// NOT NULL DEFAULT 'default' column. Wave-1 reads do not query on it;
// the column exists so a future multi-org fork can scope without a
// schema migration.
func TestSchema_TenantIDOnCommands(t *testing.T) {
	db := full.Open(t)

	var nullable, dataType string
	var defaultValue *string
	err := db.QueryRowContext(t.Context(), `
		SELECT IS_NULLABLE, DATA_TYPE, COLUMN_DEFAULT
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'commands' AND COLUMN_NAME = 'tenant_id'
	`).Scan(&nullable, &dataType, &defaultValue)
	require.NoError(t, err, "tenant_id missing from commands")
	assert.Equal(t, "NO", nullable)
	assert.Equal(t, "varchar", dataType)
	require.NotNil(t, defaultValue)
	assert.Equal(t, "default", *defaultValue)

	require.NoError(t, bootstrap.ApplySchema(t.Context(), db),
		"second ApplySchema must succeed -- migrations are not idempotent")
}
