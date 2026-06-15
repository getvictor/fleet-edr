package mysql

import (
	"errors"

	driver "github.com/go-sql-driver/mysql"
)

// permanentDataErrors are MySQL server error numbers for values that can never be stored as written: the same row will fail
// identically on every retry. They are distinguished from transient faults (deadlock, lock-wait timeout, dropped connection) that a
// retry can clear.
var permanentDataErrors = map[uint16]struct{}{
	1264: {}, // ER_WARN_DATA_OUT_OF_RANGE: value outside the column's range (e.g. a uid_t past signed INT)
	1265: {}, // ER_WARN_DATA_TRUNCATED
	1292: {}, // ER_TRUNCATED_WRONG_VALUE
	1366: {}, // ER_TRUNCATED_WRONG_VALUE_FOR_FIELD
	1406: {}, // ER_DATA_TOO_LONG
	3819: {}, // ER_CHECK_CONSTRAINT_VIOLATED
}

// IsPermanentDataError reports whether err (or any error it wraps) is a MySQL data-integrity violation that will recur on every
// retry. The graph builder drops such an event instead of failing and retrying the whole batch, so one unpersistable row cannot wedge
// the processing pipeline. Unknown errors return false (treated as transient) so genuinely retryable faults are never silently
// discarded.
func IsPermanentDataError(err error) bool {
	var me *driver.MySQLError
	if !errors.As(err, &me) {
		return false
	}
	_, ok := permanentDataErrors[me.Number]
	return ok
}
