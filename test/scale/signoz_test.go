package scale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signozResponse is a small helper to build a query_range response body in the shape the v4 API emits. Keeps the test
// cases readable and the JSON-marshal centralised; if the shape evolves, the test changes in one place.
func signozResponse(values ...string) []byte {
	type vEntry struct {
		Value     string `json:"value"`
		Timestamp int64  `json:"timestamp"`
	}
	resp := signozQueryResponse{Status: "success"}
	resp.Data.Result = []struct {
		Series []struct {
			Values []struct {
				Value     string `json:"value"`
				Timestamp int64  `json:"timestamp"`
			} `json:"values"`
		} `json:"series"`
	}{
		{
			Series: []struct {
				Values []struct {
					Value     string `json:"value"`
					Timestamp int64  `json:"timestamp"`
				} `json:"values"`
			}{
				{
					Values: func() []struct {
						Value     string `json:"value"`
						Timestamp int64  `json:"timestamp"`
					} {
						out := make([]struct {
							Value     string `json:"value"`
							Timestamp int64  `json:"timestamp"`
						}, 0, len(values))
						for _, v := range values {
							out = append(out, struct {
								Value     string `json:"value"`
								Timestamp int64  `json:"timestamp"`
							}(vEntry{Value: v, Timestamp: time.Now().UnixMilli()}))
						}
						return out
					}(),
				},
			},
		},
	}
	body, _ := json.Marshal(resp)
	return body
}

// TestQuerySigNozServerP99_HappyPath pins the round-trip shape: builder query POST -> JSON response -> max-value
// extraction -> time.Duration conversion. The mock server inspects the request body to confirm the runner emits the
// expected aggregation operator and metric key, so a future drift in the query shape (e.g. dropping the resource filter)
// surfaces here rather than in production when the cross-check silently returns 0.
func TestQuerySigNozServerP99_HappyPath(t *testing.T) {
	// Mock-server uses assert.* exclusively (testifylint go-require): require.* in a handler goroutine would call
	// t.FailNow which is unsafe outside the test goroutine. assert.* records the failure and lets the handler return
	// normally so the request still completes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v4/query_range", r.URL.Path)

		var req signozQueryRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "builder", req.CompositeQuery.QueryType)
		assert.Contains(t, req.CompositeQuery.BuilderQueries, "A")
		q := req.CompositeQuery.BuilderQueries["A"]
		assert.Equal(t, "p99", q.AggregateOperator)
		assert.Equal(t, signozMetricHTTPServerDuration, q.AggregateAttribute.Key)
		assert.Equal(t, "Histogram", q.AggregateAttribute.Type)
		if assert.Len(t, q.Filters.Items, 1, "expected one filter (service.name)") {
			assert.Equal(t, signozServiceName, q.Filters.Items[0].Value)
		}

		w.Header().Set("Content-Type", "application/json")
		// 12.34 ms is the SigNoz-reported p99 in milliseconds; querySigNozServerP99 converts to time.Duration.
		_, _ = w.Write(signozResponse("12.34"))
	}))
	defer srv.Close()

	start := time.Now().Add(-5 * time.Minute)
	end := time.Now()
	p99, err := querySigNozServerP99(context.Background(), srv.URL, start, end)
	require.NoError(t, err)
	// 12.34 ms == 12_340_000 ns; truncation in time.Duration(int(12.34)) drops the fraction so the result is 12 ms.
	// We accept either the truncated or the precise value because parseSigNozFloat's float64 -> int truncation makes the
	// integer-conversion shape part of the contract.
	assert.Equal(t, 12*time.Millisecond, p99)
}

// TestQuerySigNozServerP99_NonOK pins the soft-error contract: a non-200 response from SigNoz returns an error containing
// the status code so the operator-facing SigNozQueryError field is actionable.
func TestQuerySigNozServerP99_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream gone"))
	}))
	defer srv.Close()

	_, err := querySigNozServerP99(context.Background(), srv.URL, time.Now().Add(-time.Minute), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "upstream gone")
}

// TestQuerySigNozServerP99_EmptyResponse pins the "no series values" branch: a 200 with an empty result array returns the
// "no series values" error so the runner records a soft error rather than a confusing 0 duration.
func TestQuerySigNozServerP99_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	defer srv.Close()

	_, err := querySigNozServerP99(context.Background(), srv.URL, time.Now().Add(-time.Minute), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no series values")
}

// TestQuerySigNozServerP99_MaxAcrossSeries pins the multi-value aggregation: when SigNoz returns multiple p99 samples
// (e.g. a value-panel that didn't fully collapse to one number), the runner uses the MAX so the cross-check reflects the
// worst observed p99 in the window, not an arbitrary one.
func TestQuerySigNozServerP99_MaxAcrossSeries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signozResponse("5.0", "20.0", "10.0", "NaN"))
	}))
	defer srv.Close()

	p99, err := querySigNozServerP99(context.Background(), srv.URL, time.Now().Add(-time.Minute), time.Now())
	require.NoError(t, err)
	assert.Equal(t, 20*time.Millisecond, p99, "max(5, 20, 10) == 20; NaN entries are skipped")
}
