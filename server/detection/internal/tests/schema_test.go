//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/full"
)

// TestSchema_TenantIDOnHostsAndAlerts pins the tenant-scaffolding
// columns on detection's `hosts` and `alerts` tables:
// tenant_id VARCHAR(64) NOT NULL DEFAULT 'default' on each. Wave-1
// reads do not query on it; the column is structural scaffolding
// for wave-2 MSSP scoping.
//
// Uses testdb/full.Open so the test exercises the same full-schema
// integration path the rest of the per-context test pyramid uses.
func TestSchema_TenantIDOnHostsAndAlerts(t *testing.T) {
	db := full.Open(t)

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
}
