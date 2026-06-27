package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// White-box tests for package-private helpers. The deadlock-retry helper moved to server/sqlhelpers (and is tested there); this file
// covers the remaining detection-private helpers. The other test file (store_test.go, package mysql_test) covers the public Store API
// against a real MySQL via testdb.
func TestDeduplicateStrings(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			out := deduplicateStrings(tc.in)
			if tc.want == nil {
				assert.Nil(t, out)
				return
			}
			assert.Equal(t, tc.want, out)
		})
	}
}
