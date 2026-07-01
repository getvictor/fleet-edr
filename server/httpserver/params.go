package httpserver

import (
	"net/http"
	"strconv"
	"time"
)

// TimeRange is the canonical [from, to] in nanoseconds since Unix epoch used by every operator endpoint that filters by time. Lives in
// httpserver because the concept is generic and unrelated to any bounded context's domain logic; detection/api re-exports it via type
// alias so existing call sites compile unchanged.
type TimeRange struct {
	FromNs int64
	ToNs   int64
}

// ParseIntParam reads an int query parameter, returning defaultVal when the parameter is absent or unparseable. Used by handlers that
// accept ?limit=100 / ?process_id=42 style filters.
func ParseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// ParseInt64Param reads an int64 query parameter, returning defaultVal when the parameter is absent or unparseable. Used for
// nanosecond timestamps and BIGINT row IDs.
func ParseInt64Param(r *http.Request, name string, defaultVal int64) int64 {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return v
}

// ParseBoolParam reads a boolean query parameter, returning defaultVal when the parameter is absent or unparseable. Accepts the
// strconv.ParseBool set (1/t/T/TRUE/true/True and their false counterparts) so ?flatten=1 and ?flatten=true both read as true.
func ParseBoolParam(r *http.Request, name string, defaultVal bool) bool {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// ParseTimeRange reads ?from=<ns>&to=<ns> from the request. Defaults to the last hour when either parameter is absent or unparseable
// so the operator UI's "show recent activity" page never returns 400.
func ParseTimeRange(r *http.Request) TimeRange {
	now := time.Now().UnixNano()
	defaultFrom := now - int64(time.Hour)
	return TimeRange{
		FromNs: ParseInt64Param(r, "from", defaultFrom),
		ToNs:   ParseInt64Param(r, "to", now),
	}
}
