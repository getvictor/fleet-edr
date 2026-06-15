package graph

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	driver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

// TestPermanentError pins which per-event failures the builder drops (so they cannot wedge the batch) versus retries. Parse failures
// and MySQL data-integrity violations recur on every retry and must be permanent; transient DB faults and unclassified errors must
// not be dropped. See issue #379.
func TestPermanentError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"json type error (e.g. uid overflow on 32-bit)", &json.UnmarshalTypeError{Value: "number", Type: nil}, true},
		{"json syntax error", &json.SyntaxError{}, true},
		{"wrapped json type error", fmt.Errorf("decode exec payload: %w", &json.UnmarshalTypeError{}), true},
		{"mysql out-of-range is delegated as permanent", &driver.MySQLError{Number: 1264}, true},
		{"transient mysql deadlock is not permanent", &driver.MySQLError{Number: 1213}, false},
		{"generic error is not permanent", errors.New("dial tcp: connection refused"), false},
		{"nil is not permanent", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, permanentError(tc.err))
		})
	}
}
