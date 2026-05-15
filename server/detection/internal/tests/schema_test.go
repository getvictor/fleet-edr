//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/testdb/full"
)

// TestSchema_NoTenantIDOnHostsAndAlerts pins the removal of the legacy
// tenant_id scaffolding column on detection's `hosts` and `alerts`
// tables. The product is a single-instance deployment, so the column
// was dropped; a regression that re-introduces it silently is caught
// here.
func TestSchema_NoTenantIDOnHostsAndAlerts(t *testing.T) {
	db := full.Open(t)

	for _, table := range []string{"hosts", "alerts"} {
		t.Run(table, func(t *testing.T) {
			var n int
			err := db.QueryRowContext(t.Context(), `
				SELECT COUNT(*)
				FROM INFORMATION_SCHEMA.COLUMNS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'tenant_id'
			`, table).Scan(&n)
			assert.NoError(t, err)
			assert.Zero(t, n, "tenant_id must not be re-introduced on %s; the product is single-instance", table)
		})
	}
}
