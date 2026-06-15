package mysql

import (
	"errors"
	"fmt"
	"testing"

	driver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

// TestIsPermanentDataError pins which MySQL failures the graph builder treats as poison (drop the event, advance the batch) versus
// transient (fail the batch so the processor retries). Getting this wrong in either direction is a regression: classifying a transient
// fault as permanent silently drops good data, and classifying a permanent fault as transient re-introduces the uid/gid-overflow
// wedge where one bad row stalls the pipeline forever.
func TestIsPermanentDataError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"out-of-range uid (1264)", &driver.MySQLError{Number: 1264, Message: "Out of range value for column 'uid' at row 1"}, true},
		{"data too long (1406)", &driver.MySQLError{Number: 1406, Message: "Data too long for column 'host_id'"}, true},
		{"check constraint violated (3819)", &driver.MySQLError{Number: 3819}, true},
		{"bad null (1048)", &driver.MySQLError{Number: 1048}, true},
		{"duplicate entry (1062)", &driver.MySQLError{Number: 1062}, true},
		{"no default for field (1364)", &driver.MySQLError{Number: 1364}, true},
		{"wrapped out-of-range is still permanent", fmt.Errorf("insert process: %w", &driver.MySQLError{Number: 1264}), true},
		// spec:server-process-graph-builder/a-single-unpersistable-event-does-not-stall-batch-processing/a-transient-failure-retries-the-batch
		{"deadlock (1213) is transient", &driver.MySQLError{Number: 1213}, false},
		{"lock wait timeout (1205) is transient", &driver.MySQLError{Number: 1205}, false},
		{"non-mysql error is transient", errors.New("dial tcp: connection refused"), false},
		{"nil error is not permanent", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, IsPermanentDataError(tc.err))
		})
	}
}
