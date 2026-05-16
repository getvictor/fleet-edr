package testdb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
)

// TestOpen_ReturnsUsableEmptyDB pins that testdb.Open hands back a connected DB that the caller can run DDL + DML against. The fixture
// applies no schemas; that's the caller's responsibility (see the testdb/full sub-package for the all-context wrapper).
func TestOpen_ReturnsUsableEmptyDB(t *testing.T) {
	db := testdb.Open(t)
	_, err := db.ExecContext(t.Context(),
		`CREATE TABLE smoke (id INT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO smoke VALUES (1)`)
	require.NoError(t, err)
}
