package mysql

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

// isDeadlockErr is the gatekeeper for the insert-retry loop; if it misclassifies, the retry either fires on
// the wrong error class (potentially looping on a non-transient failure) or never fires when the deadlock
// shows up wrapped (the production path wraps with fmt.Errorf("insert %s: %w", ...)).
func TestIsDeadlockErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a deadlock", nil, false},
		{"plain error is not a deadlock", errors.New("connection refused"), false},
		{"different mysql error (1062 dup key)", &mysql.MySQLError{Number: 1062, Message: "duplicate"}, false},
		{"bare deadlock error", &mysql.MySQLError{Number: 1213, Message: "Deadlock found"}, true},
		{"wrapped deadlock error", fmt.Errorf("insert evt-1: %w",
			&mysql.MySQLError{Number: 1213, Message: "Deadlock found"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isDeadlockErr(tc.err))
		})
	}
}

// White-box tests for package-private helpers. The other test file (store_test.go, package mysql_test) covers the public Store API
// against a real MySQL via testdb.
func TestDeduplicateStrings(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
		{"single element passthrough", []string{"a"}, []string{"a"}},
		{"all unique", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all duplicates", []string{"x", "x", "x"}, []string{"x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := deduplicateStrings(tc.in)
			if tc.want == nil {
				assert.Nil(t, out)
				return
			}
			assert.Equal(t, tc.want, out)
		})
	}
}
