package bootstrap

import (
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_RejectsMissingDB(t *testing.T) {
	_, err := New(Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}

func TestMigrationStep_ShouldIgnore(t *testing.T) {
	step := migrationStep{
		Name:         "ttest",
		IgnoreErrors: []uint16{mysqlDuplicateColumn, mysqlNoSuchFK},
	}

	assert.False(t, step.shouldIgnore(nil), "nil error never ignored")
	assert.False(t, step.shouldIgnore(errors.New("plain")),
		"plain non-mysql errors aren't ignored")

	dup := &mysql.MySQLError{Number: mysqlDuplicateColumn}
	assert.True(t, step.shouldIgnore(dup), "duplicate-column code is ignored")

	wrapped := errors.New("wrap")
	wrapped = &mysql.MySQLError{Number: mysqlNoSuchFK, Message: wrapped.Error()}
	assert.True(t, step.shouldIgnore(wrapped))

	other := &mysql.MySQLError{Number: 9999}
	assert.False(t, step.shouldIgnore(other),
		"unlisted MySQL codes are NOT ignored")
}
