package scale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

// SigNoz cross-check defaults. The metric name + service tag are the SigNoz / OTel conventions for HTTP-server instrumentation
// the EDR server uses (see server/observability for the wiring). Operators whose SigNoz install indexes the metric under a
// different name can override via Options fields once those are added (kept narrow for v2; expose if the cross-check needs
// per-deployment knobs).
const (
	// signozMetricHTTPServerDuration is the stable-semconv histogram for HTTP server request duration, reported in SECONDS.
	//
	// It must NOT be the older `http.server.duration` (milliseconds). Both names exist in our SigNoz because other services on the
	// shared instance still emit the old one, so querying it succeeds and returns somebody else's numbers rather than failing
	// (issue #734). Verified against the live instance: `http.server.request.duration` is emitted by `fleet-edr-server`, and
	// `http.server.duration` is not.
	signozMetricHTTPServerDuration = "http.server.request.duration"

	// signozServiceName is the service.name the EDR server emits under: `serviceName` in server/cmd/fleet-edr-server/main.go, a
	// hardcoded constant rather than an env override.
	//
	// It must NOT be "fleet". That is the MDM Fleet server, a DIFFERENT PRODUCT that shares this SigNoz instance, and it does emit
	// `http.server.duration`. The pre-#734 pairing of "fleet" + `http.server.duration` was therefore a perfectly valid query that
	// silently returned the other product's HTTP latency and recorded it as this run's server-side p99.
	signozServiceName = "fleet-edr-server"

	// signozHTTPTimeout caps the cross-check HTTP call. A SigNoz query against the run's 30-min window typically returns in
	// well under 1s; the 10s ceiling here is generous so a stop-the-world GC pause inside SigNoz doesn't propagate as a soft
	// "query failed" diagnostic on the report.
	signozHTTPTimeout = 10 * time.Second

	// signozQueryStep controls SigNoz's resampling resolution. 60s is the SigNoz Cloud default for value-panel queries and is
	// fine-grained enough to capture p99 swings within a 30-min run without producing a huge response payload.
	signozQueryStep = 60

	// signozResponseLimit caps how many bytes of the SigNoz response body the runner reads. 1 MiB is well above the size of a
	// well-formed value-panel response (typically <10 KiB) but bounds the memory footprint if SigNoz returns an unexpected
	// HTML error page or a paginated chunk that didn't terminate.
	signozResponseLimit = 1 << 20

	// signozErrorBodyMax caps how much of a non-200 response body lands in the soft-error string. Keeps a multi-KB SigNoz
	// error page from making Report.SigNozQueryError unreadable.
	signozErrorBodyMax = 256
)

// signozQueryRequest is the minimal v4 builder-query envelope SigNoz accepts on POST /api/v4/query_range. The shape mirrors what
// the SigNoz UI emits for a value-panel p99 query against a Histogram-typed metric.
//
// Reference: SigNoz query-service v0.40+. If the API contract drifts (older self-hosted installs were on v3 with a different
// envelope), an operator-facing soft error from the query is the operating mode: the cross-check is a diagnostic, not a gate,
// so a "the SigNoz here speaks v3, the scale runner expects v4" mismatch surfaces in Report.SigNozQueryError and does not flip
// the Pass bool.
type signozQueryRequest struct {
	Start          int64                `json:"start"`
	End            int64                `json:"end"`
	Step           int64                `json:"step"`
	CompositeQuery signozCompositeQuery `json:"compositeQuery"`
}

type signozCompositeQuery struct {
	QueryType      string                        `json:"queryType"`
	PanelType      string                        `json:"panelType"`
	BuilderQueries map[string]signozBuilderQuery `json:"builderQueries"`
}

type signozBuilderQuery struct {
	QueryName          string                   `json:"queryName"`
	DataSource         string                   `json:"dataSource"`
	AggregateOperator  string                   `json:"aggregateOperator"`
	AggregateAttribute signozAggregateAttribute `json:"aggregateAttribute"`
	Filters            signozFilterSet          `json:"filters"`
	Expression         string                   `json:"expression"`
	Disabled           bool                     `json:"disabled"`
}

type signozAggregateAttribute struct {
	Key      string `json:"key"`
	DataType string `json:"dataType"`
	Type     string `json:"type"`
}

type signozFilterSet struct {
	Op    string         `json:"op"`
	Items []signozFilter `json:"items"`
}

type signozFilter struct {
	Key   signozFilterKey `json:"key"`
	Op    string          `json:"op"`
	Value string          `json:"value"`
}

type signozFilterKey struct {
	Key      string `json:"key"`
	DataType string `json:"dataType"`
	Type     string `json:"type"`
}

// signozQueryResponse is the minimum subset of the SigNoz response shape the runner reads. The full envelope has many more
// fields (status, message, data wrapping, etc.); pinning only what we need keeps the parser resilient to additive changes.
type signozQueryResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []struct {
			Series []struct {
				Values []struct {
					Value     string `json:"value"`     // SigNoz returns numbers as strings in this field
					Timestamp int64  `json:"timestamp"` // milliseconds since epoch
				} `json:"values"`
			} `json:"series"`
		} `json:"result"`
	} `json:"data"`
}

// querySigNozServerP99 issues a v4 builder query against the SigNoz at baseURL and returns the maximum p99 value observed
// across the response time series for [start, end]. SigNoz reports this metric in its native unit, SECONDS, so the runner
// scales by time.Second. If the response carries no values, returns 0 + a soft error so the caller can record
// SigNozQueryError without aborting the run.
func querySigNozServerP99(ctx context.Context, baseURL string, start, end time.Time) (time.Duration, error) {
	reqBody := signozQueryRequest{
		Start: start.UnixMilli(),
		End:   end.UnixMilli(),
		Step:  signozQueryStep,
		CompositeQuery: signozCompositeQuery{
			QueryType: "builder",
			PanelType: "value",
			BuilderQueries: map[string]signozBuilderQuery{
				"A": {
					QueryName:         "A",
					DataSource:        "metrics",
					AggregateOperator: "p99",
					AggregateAttribute: signozAggregateAttribute{
						Key:      signozMetricHTTPServerDuration,
						DataType: "float64",
						Type:     "Histogram",
					},
					Filters: signozFilterSet{
						Op: "AND",
						Items: []signozFilter{
							{
								Key: signozFilterKey{
									Key:      "service.name",
									DataType: "string",
									Type:     "resource",
								},
								Op:    "=",
								Value: signozServiceName,
							},
						},
					},
					Expression: "A",
				},
			},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("marshal signoz query: %w", err)
	}

	httpCtx, cancel := context.WithTimeout(ctx, signozHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httpCtx, http.MethodPost, baseURL+"/api/v4/query_range", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build signoz request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("signoz query: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, signozResponseLimit))
	if err != nil {
		return 0, fmt.Errorf("read signoz response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("signoz HTTP %d: %s", resp.StatusCode, truncateForError(respBody, signozErrorBodyMax))
	}

	var parsed signozQueryResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return 0, fmt.Errorf("decode signoz response: %w", err)
	}
	maxValue, ok := extractMaxValue(parsed)
	if !ok {
		return 0, errors.New("signoz response has no series values")
	}
	// `http.server.request.duration` is declared in SECONDS (the stable HTTP semconv unit; the superseded
	// `http.server.duration` was milliseconds). Measured on the live instance to be sure rather than trusting the unit
	// metadata alone: p50 is 0.00879 and p99 is 1.083, which reads as 8.79ms / 1.08s. Under a milliseconds reading the p50
	// would be 8.79 MICROseconds for a request that touches MySQL, which is not physically possible.
	//
	// Multiply the float AGAINST float64(time.Second) before the time.Duration cast so sub-second values survive; the
	// `time.Duration(maxValue) * time.Second` shape would truncate 0.008 to 0 (the same precision trap as Gemini +
	// CodeRabbit #277, which caught it when this was milliseconds).
	return time.Duration(maxValue * float64(time.Second)), nil
}

// extractMaxValue walks every series x value in the response and returns the largest p99 value observed. SigNoz returns one
// series per attribute combination; for a single-filter query the result is typically one series with one value (the
// requested value-panel aggregate) but the parser handles multi-series shapes defensively. Returns (0, false) when no value
// could be parsed. The inner per-series loop is extracted to maxValueInSeries so this function stays under Sonar's S3776
// cognitive-complexity budget (the original three-deep nested loop with mixed error/NaN handling was at 16 vs 15 allowed).
func extractMaxValue(parsed signozQueryResponse) (float64, bool) {
	var best float64
	var found bool
	for _, result := range parsed.Data.Result {
		for _, series := range result.Series {
			if v, ok := maxValueInSeries(series.Values); ok && (!found || v > best) {
				best = v
				found = true
			}
		}
	}
	return best, found
}

// maxValueInSeries returns the largest parseable, non-NaN value in a single series' Values slice. Splitting this out of
// extractMaxValue's loop keeps the outer iteration linear (Sonar S3776). Returns (0, false) for an empty / all-NaN / all-
// unparseable series.
func maxValueInSeries(values []struct {
	Value     string `json:"value"`
	Timestamp int64  `json:"timestamp"`
},
) (float64, bool) {
	var best float64
	var found bool
	for _, v := range values {
		parsedVal, err := parseSigNozFloat(v.Value)
		if err != nil || math.IsNaN(parsedVal) {
			continue
		}
		if !found || parsedVal > best {
			best = parsedVal
			found = true
		}
	}
	return best, found
}

// parseSigNozFloat parses one SigNoz numeric value. The query API returns numbers as strings ("NaN", "12.34") so the runner
// uses a small helper rather than relying on json.Number tagging on the response struct. Uses strconv.ParseFloat over the
// previous fmt.Sscanf shape: ParseFloat is the standard, much faster path for a known-shape float string (Gemini #277).
func parseSigNozFloat(s string) (float64, error) {
	if s == "" || s == "NaN" {
		return math.NaN(), nil
	}
	return strconv.ParseFloat(s, 64)
}

// truncateForError trims a possibly-large response body for inclusion in an error string. Avoids dumping a multi-MB SigNoz
// HTML error page into the soft-error field on Report.SigNozQueryError. The parameter name is `maxLen` rather than `max`
// to avoid shadowing the Go 1.21+ builtin (revive redefines-builtin-id).
func truncateForError(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "...(truncated)"
}
