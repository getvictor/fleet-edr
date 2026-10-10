package tracing

import (
	"context"
	"database/sql/driver"

	"github.com/XSAM/otelsql"
	"go.opentelemetry.io/otel/trace"
)

// SQLSpanOptions is the span policy every otelsql-wrapped pool in the server opens with (MySQL and the ClickHouse event archive), so
// the two stores cannot drift apart in what they export.
//
//   - A database call with no active span records nothing. A root database span belongs to no request and no batch, so nothing can
//     reach it from an alert or a slow request, and the route-tier sampler sees it as unclassified and keeps every one: background
//     polling exported several hundred thousand of them an hour. Work worth tracing starts its own root span first (see the
//     detection processor and the periodic sweeps), and its queries then appear under it.
//   - The connection housekeeping spans (session reset, statement prepare, row iteration) are omitted. They tripled the span count
//     of every query while the query span already carries the statement and its latency.
//   - driver.ErrSkip is not recorded as an error. It is a benign control-flow sentinel: the MySQL driver returns it whenever
//     interpolateParams=false (the secure default) sends a parametrized query down the prepare path.
//
// Database latency metrics are unaffected: otelsql records them for every call whether or not a span is created.
func SQLSpanOptions() otelsql.SpanOptions {
	return otelsql.SpanOptions{
		DisableErrSkip:       true,
		OmitConnResetSession: true,
		OmitConnPrepare:      true,
		OmitRows:             true,
		SpanFilter:           hasParentSpan,
	}
}

func hasParentSpan(ctx context.Context, _ otelsql.Method, _ string, _ []driver.NamedValue) bool {
	return trace.SpanContextFromContext(ctx).IsValid()
}
