//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestSchema_NoTenantIDOnCommands pins the removal of the legacy tenant_id scaffolding column on response's `commands` table.
// The product is a single-instance deployment, so the column was dropped; a regression that re-introduces it silently is caught here.
// The follow-up ApplySchema call verifies the boot-time re-apply remains idempotent.
func TestSchema_NoTenantIDOnCommands(t *testing.T) {
	db := full.Open(t)

	var n int
	err := db.QueryRowContext(t.Context(), `
		SELECT COUNT(*)
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'commands' AND COLUMN_NAME = 'tenant_id'
	`).Scan(&n)
	require.NoError(t, err)
	assert.Zero(t, n, "tenant_id must not be re-introduced on commands; the product is single-instance")

	require.NoError(t, bootstrap.ApplySchema(t.Context(), db),
		"second ApplySchema must succeed -- migrations are not idempotent")
}
