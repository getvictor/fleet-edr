package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplySchema_NilDBRejected exercises the nil-DB guard so a caller
// that wires bootstrap without a DB gets a typed error instead of a
// nil deref deep inside the loop.
func TestApplySchema_NilDBRejected(t *testing.T) {
	err := ApplySchema(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}

// TestIsAlreadyAppliedMigration covers the three branches the helper
// distinguishes: non-MySQL error, unmatched MySQL code, and a code
// from the idempotency-safe set. Mirrors the identity/bootstrap
// helper test so the two stay in lockstep.
func TestIsAlreadyAppliedMigration(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "non-mysql error", err: errors.New("some other failure"), want: false},
		{name: "unmatched mysql code", err: &mysql.MySQLError{Number: 1234}, want: false},
		{name: "duplicate column (1060)", err: &mysql.MySQLError{Number: 1060}, want: true},
		{name: "duplicate key name (1061)", err: &mysql.MySQLError{Number: 1061}, want: true},
		{name: "duplicate FK name (1826)", err: &mysql.MySQLError{Number: 1826}, want: true},
		{name: "older duplicate-key code (1022)", err: &mysql.MySQLError{Number: 1022}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isAlreadyAppliedMigration(tc.err))
		})
	}
}
