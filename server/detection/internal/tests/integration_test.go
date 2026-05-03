//go:build integration

// Per-context integration tests for the detection bounded context.
// Exercise the full bootstrap.New -> ApplySchema + MigrateSchema ->
// Service stack against a real MySQL. Skips when EDR_TEST_DSN isn't
// set, matching the project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/testdb/full"
)

// stubUserExists is a closure-typed UserExists fixture. Tests pin the
// known-user set up front; UpdateAlertStatus consults it for the
// FK-replacement check (the cross-context guard that replaces
// fk_alerts_updated_by).
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

// stubRule is a minimal rules.api.Rule that emits one finding for
// every "trigger" event in the batch. Used by the engine + processor
// tests that need a deterministic rule signal without dragging in
// any production rule's allowlist + tuning.
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

// recordingMetrics captures every hook invocation so tests can assert
// observability survived the phase-5 wiring rewrite.
type recordingMetrics struct {
	mu                  sync.Mutex
	eventsIngested      int
	dbQueries           int
	alertsCreated       int
	processesReconciled int64
	rowsDeleted         int64
}

func (m *recordingMetrics) EventsIngested(_ context.Context, _ string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventsIngested += n
}
func (m *recordingMetrics) ObserveDBQuery(_ context.Context, _ string, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dbQueries++
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

func (m *recordingMetrics) snapshot() (events, queries, alerts int, reconciled, deleted int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventsIngested, m.dbQueries, m.alertsCreated, m.processesReconciled, m.rowsDeleted
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
	}
	d, err := bootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, d.ApplySchema(t.Context()))
	require.NoError(t, d.MigrateSchema(t.Context()))

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

// withHostID pins host_id on the request context the way the real
// endpoint.HostToken middleware does. Lets the ingest handler tests
// run without spinning up endpoint bootstrap + a token mint.
func withHostID(next http.Handler, hostID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := endpointapi.WithHostIDForTest(r.Context(), hostID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---- Ingest tests -----------------------------------------------------------

func TestIngest_PersistsEvents(t *testing.T) {
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

func TestIngest_HostIDMismatchRejected(t *testing.T) {
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

// ---- Engine + processor tests ----------------------------------------------

func TestEngine_EvaluatesAndPersistsAlerts(t *testing.T) {
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

	// One processor tick is enough; ProcessOnce is exposed on the
	// processor for deterministic test signalling. Use a brief
	// busy-loop on Run to converge.
	require.Eventually(t, func() bool {
		alerts, _ := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
		return len(alerts) > 0
	}, 5*time.Second, 50*time.Millisecond, "expected stub rule to produce an alert")

	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, "stub", alerts[0].RuleID)
	assert.Equal(t, rulesapi.SeverityHigh, alerts[0].Severity)
	_ = procID // unused but documents the FK satisfaction
}

func TestEngine_DedupSilencesRepeatRuleHits(t *testing.T) {
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

	// The unique key is (host_id, rule_id, process_id); two trigger
	// events from the same rule against the same process must collapse
	// into ONE alert row regardless of how many triggers we sent.
	alerts, err := d.Service().ListAlerts(ctx, api.AlertFilter{HostID: "host-a"})
	require.NoError(t, err)
	assert.Len(t, alerts, 1)
}

// ---- Operator alert lifecycle tests ----------------------------------------

func TestOperator_UpdateAlertStatus_HappyPath(t *testing.T) {
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

func TestOperator_GetAlert_ReturnsCorrelatedEventIDs(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	alertID := seedSingleAlert(t, ctx, d)

	alert, eventIDs, err := d.Service().GetAlert(ctx, alertID)
	require.NoError(t, err)
	assert.Equal(t, alertID, alert.ID)
	assert.NotEmpty(t, eventIDs, "alert must surface its triggering event ids")
}

func TestOperator_GetAlert_NotFound(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	_, _, err := d.Service().GetAlert(ctx, 999_999)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAlertNotFound)
}

func TestOperator_ListAlerts_FiltersByHostAndStatus(t *testing.T) {
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
}

// ---- Heartbeat / metrics gauges --------------------------------------------

func TestRecordHostSeen_AdvancesLastSeen(t *testing.T) {
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

func TestService_CountOfflineHosts(t *testing.T) {
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

func TestBootstrap_IntakeModeIsNoOp(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeIntake})

	// Intake mode skips the operator surface, so the service has no
	// engine wired and LoadActive is a no-op (the intake binary
	// doesn't evaluate rules). RegisterAuthedRoutes must also be a
	// no-op so cmd/main can call it unconditionally.
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
	_, err := bootstrap.New(bootstrap.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB")
}

func TestBootstrap_SchemaIdempotent(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()
	// ApplySchema + MigrateSchema MUST be re-runnable without error
	// (existing-DB upgrades go through the same path).
	require.NoError(t, d.ApplySchema(ctx))
	require.NoError(t, d.MigrateSchema(ctx))
	require.NoError(t, d.ApplySchema(ctx))
	require.NoError(t, d.MigrateSchema(ctx))
}

// ---- Metrics propagation ---------------------------------------------------

func TestSetMetrics_PropagatesToEngineAndIntake(t *testing.T) {
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
		_, _, alerts, _, _ := rec.snapshot()
		return alerts > 0
	}, 5*time.Second, 50*time.Millisecond)

	events, queries, alerts, _, _ := rec.snapshot()
	assert.Positive(t, events, "EventsIngested hook fired by intake")
	assert.Positive(t, queries, "ObserveDBQuery fired during ingest")
	assert.Positive(t, alerts, "AlertCreated fired by engine")
}

// ---- Graph builder exec/exit paths -----------------------------------------

func TestGraph_BuildsTreeFromExecBatch(t *testing.T) {
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	// python (50) -> sh (100) -> /tmp/payload (200). Three forks +
	// three execs exercises handleFork, handleExec, the parent-path
	// inheritance in fork-without-exec, and the tree builder's
	// ppid -> pid linkage.
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

	require.Eventually(t, func() bool {
		tree, err := d.Service().BuildTree(ctx, "h",
			api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}, 100)
		if err != nil {
			return false
		}
		return countNodes(tree) >= 3
	}, 5*time.Second, 50*time.Millisecond, "expected 3 process rows materialised")

	tree, err := d.Service().BuildTree(ctx, "h",
		api.TimeRange{FromNs: now - int64(time.Hour), ToNs: now + int64(time.Hour)}, 100)
	require.NoError(t, err)
	assert.NotEmpty(t, tree, "BuildTree must return at least one root")

	// At least one process must have a non-empty path that points at
	// /usr/bin/python3 (the chain root).
	paths := flattenPaths(tree)
	assert.Contains(t, paths, "/usr/bin/python3")
	assert.Contains(t, paths, "/bin/sh")
	assert.Contains(t, paths, "/tmp/payload")
}

func TestGraph_HandlesExitEvent(t *testing.T) {
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

	// Query at the exit time exactly: GetProcessByPID's predicate is
	// (exit_time_ns IS NULL OR exit_time_ns >= ?), so the row is
	// reachable at its exit time and earlier, then drops out.
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, "h", 777, now+2)
		if err != nil || p == nil {
			return false
		}
		return p.Process.ExitTimeNs != nil
	}, 5*time.Second, 50*time.Millisecond, "exit event must stamp exit_time_ns")
}

func TestGraph_ExecWithoutFork(t *testing.T) {
	// Issue #7 / boot sequence: agent restart can deliver an exec
	// without the originating fork (we missed it). The builder
	// synthesizes a root row with fork_time_ns == exec time.
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

func TestGraph_SamePIDReExec(t *testing.T) {
	// Issue #10: shell exec-optimization. python -> sh -c "<binary>"
	// re-execs the binary on the SAME pid without forking. The
	// builder must close the prior generation and link the new one
	// via previous_exec_id.
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

// ---- Operator HTTP handler -------------------------------------------------

func TestOperatorHTTP_ListHosts(t *testing.T) {
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

func TestOperatorHTTP_GetAlert_NotFound(t *testing.T) {
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

func TestOperatorHTTP_GetAlert_BadID(t *testing.T) {
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

func TestOperatorHTTP_UpdateAlertStatus_HappyPath(t *testing.T) {
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

func TestOperatorHTTP_UpdateAlertStatus_InvalidStatus(t *testing.T) {
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
}

func TestOperatorHTTP_ProcessTree_RequiresHostID(t *testing.T) {
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
	// Empty path segment yields a 404 from the mux (the path matcher
	// doesn't accept the empty {host_id}). Either 400 or 404 is
	// acceptable; just confirm it's NOT 200.
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestOperatorHTTP_ProcessDetail_BadPID(t *testing.T) {
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

func TestOperatorHTTP_ProcessDetail_NotFound(t *testing.T) {
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

func TestOperatorHTTP_ProcessTree_HappyPath(t *testing.T) {
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

// ---- Health probes ---------------------------------------------------------

func TestHealthRoutes_LivezReadyz(t *testing.T) {
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

// (Wire decode + Marshal/Unmarshal for NullRawJSON are tested in the
// detection/api package's own _test.go file alongside these
// integration tests.)

// ---- Cross-context heartbeat (response -> detection) ----------------------

func TestRecordHostSeen_SatisfiesResponseHeartbeatShape(t *testing.T) {
	// The response context wires its Heartbeat closure to
	// detectionCtx.Service().RecordHostSeen. This test pins the
	// signature compatibility so a future signature drift breaks the
	// build via the type alias check below rather than at runtime.
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})

	// Wrapping in a function literal with the exact heartbeat signature pins the shape:
	// if RecordHostSeen drifts away from what the response context's Heartbeat closure
	// expects, this fails to compile rather than at runtime.
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

// insertEventsViaIngest sends the batch through the agent-facing
// IngestHandler so the test exercises the same path production uses
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

// mustInsertProcess seeds a process row (so subsequent alerts can
// reference its id via fk_alerts_process). Uses the public Service
// surface so the helper doesn't reach into detection/internal/mysql
// from outside detection/.
func mustInsertProcess(t *testing.T, ctx context.Context, d *bootstrap.Detection, hostID string, pid int) int64 {
	t.Helper()
	insertEventsViaIngest(ctx, t, d, hostID, []api.Event{
		{
			EventID:     "fork-seed-" + hostID,
			HostID:      hostID,
			TimestampNs: 1,
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

// insertAlertDirect drives one alert through the engine path for the
// given host. ruleID picks the dedup key; the stub rule's
// ProcessID=1 happens to resolve against the seed process row this
// helper relies on having been inserted by mustInsertProcess up front.
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
