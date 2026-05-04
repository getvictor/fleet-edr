//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/bootstrap"
	"github.com/fleetdm/edr/server/testdb"
)

// TestSchema_TenantIDOnHostsAndAlerts locks in the wave-1
// tenant-scaffolding migration: detection's `hosts` and `alerts`
// tables both gain a tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'
// column. Wave-1 reads do not query on it; the column is structural
// scaffolding for wave-2 MSSP scoping.
func TestSchema_TenantIDOnHostsAndAlerts(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, bootstrap.ApplySchema(t.Context(), db))
	require.NoError(t, bootstrap.MigrateSchema(t.Context(), db))

	for _, table := range []string{"hosts", "alerts"} {
		t.Run(table, func(t *testing.T) {
			var nullable, dataType string
			var defaultValue *string
			err := db.QueryRowContext(t.Context(), `
				SELECT IS_NULLABLE, DATA_TYPE, COLUMN_DEFAULT
				FROM INFORMATION_SCHEMA.COLUMNS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'tenant_id'
			`, table).Scan(&nullable, &dataType, &defaultValue)
			require.NoErrorf(t, err, "tenant_id missing from %s", table)
			assert.Equal(t, "NO", nullable)
			assert.Equal(t, "varchar", dataType)
			require.NotNil(t, defaultValue)
			assert.Equal(t, "default", *defaultValue)
		})
	}

	// Idempotency: re-running migrations is safe (an upgrade flow never
	// calls ApplySchema once on a fresh DB plus a stop-the-world freeze;
	// it calls both ApplySchema and MigrateSchema unconditionally).
	require.NoError(t, bootstrap.MigrateSchema(t.Context(), db),
		"MigrateSchema must be idempotent on a populated DB")
}
