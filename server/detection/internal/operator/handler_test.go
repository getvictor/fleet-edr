package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// fakeService is the closure-driven detection api.Service stub. Methods relevant to operator routes are pinned per-test via the
// matching closure; methods the operator handler never reaches panic so an accidental call surfaces immediately. Mirrors the shape
// of server/response/internal/operator/handler_test.go's fakeService for cross-package consistency.
type fakeService struct {
	listHosts         func(ctx context.Context) ([]api.HostSummary, error)
	buildTree         func(ctx context.Context, hostID string, tr api.TimeRange, limit int) ([]api.ProcessNode, error)
	getProcessDetail  func(ctx context.Context, hostID string, pid int, atNs int64) (*api.ProcessDetail, error)
	listAlerts        func(ctx context.Context, filter api.AlertFilter) ([]api.Alert, error)
	getAlert          func(ctx context.Context, id int64) (api.Alert, []string, error)
	getAlertEvidence  func(ctx context.Context, id int64) ([]api.Event, error)
	updateAlertStatus func(ctx context.Context, id int64, status api.AlertStatus, actorID string) (api.Alert, error)
}

// GetAlertEvidence returns nil (no payloads) when unset, so existing GetAlert handler tests keep passing without wiring evidence.
func (f fakeService) GetAlertEvidence(ctx context.Context, id int64) ([]api.Event, error) {
	if f.getAlertEvidence == nil {
		return nil, nil
	}
	return f.getAlertEvidence(ctx, id)
}

func (f fakeService) ListHosts(ctx context.Context) ([]api.HostSummary, error) {
	if f.listHosts == nil {
		panic("fakeService.ListHosts not set")
	}
	return f.listHosts(ctx)
}

func (f fakeService) BuildTree(ctx context.Context, hostID string, tr api.TimeRange, limit int) ([]api.ProcessNode, error) {
	if f.buildTree == nil {
		panic("fakeService.BuildTree not set")
	}
	return f.buildTree(ctx, hostID, tr, limit)
}

func (f fakeService) GetProcessDetail(ctx context.Context, hostID string, pid int, atNs int64) (*api.ProcessDetail, error) {
	if f.getProcessDetail == nil {
		panic("fakeService.GetProcessDetail not set")
	}
	return f.getProcessDetail(ctx, hostID, pid, atNs)
}

func (f fakeService) ListAlerts(ctx context.Context, filter api.AlertFilter) ([]api.Alert, error) {
	if f.listAlerts == nil {
		panic("fakeService.ListAlerts not set")
	}
	return f.listAlerts(ctx, filter)
}

func (f fakeService) GetAlert(ctx context.Context, id int64) (api.Alert, []string, error) {
	if f.getAlert == nil {
		panic("fakeService.GetAlert not set")
	}
	return f.getAlert(ctx, id)
}

func (f fakeService) UpdateAlertStatus(ctx context.Context, id int64, status api.AlertStatus, actorID string) (api.Alert, error) {
	if f.updateAlertStatus == nil {
		panic("fakeService.UpdateAlertStatus not set")
	}
	return f.updateAlertStatus(ctx, id, status, actorID)
}

// Methods the operator handler never reaches but the interface requires. Panic on call so a regression that newly invokes them
// from a handler path fails the test loudly.
func (f fakeService) RecordHostSeen(context.Context, string, time.Time) error {
	panic("fakeService.RecordHostSeen: operator routes do not call this")
}
func (f fakeService) CountOfflineHosts(context.Context, time.Duration) (int, error) {
	panic("fakeService.CountOfflineHosts: operator routes do not call this")
}
func (f fakeService) CountUnprocessed(context.Context) (int64, error) {
	panic("fakeService.CountUnprocessed: operator routes do not call this")
}
func (f fakeService) IngestHandler() http.Handler {
	panic("fakeService.IngestHandler: operator routes do not call this")
}

// allowAllAuthZ + denyAllAuthZ pin the two HTTPGate outcomes the handler branches on. The role-matrix coverage lives in
// server/identity/internal/authz/engine_test.go; these stubs only need to exercise the allow / deny gate behaviour the handler sees.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

type denyAllAuthZ struct{}

func (denyAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: false, Reason: "denied_by_test"}, nil
}

// recAudit captures audit calls so happy-path tests can assert the alert.update audit row fires. RecordHostSeen and others have no
// audit emission so the operator-handler audit surface is small and easy to enumerate.
type recAudit struct{ events []identityapi.AuditEvent }

func (r *recAudit) Record(_ context.Context, evt identityapi.AuditEvent) error {
	r.events = append(r.events, evt)
	return nil
}

func newOperatorServer(t *testing.T, svc api.Service, az identityapi.AuthZ) *httptest.Server {
	t.Helper()
	h := New(svc, az, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestNew_NilServicePanics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "detection operator.New: api.Service must not be nil", func() {
		New(nil, allowAllAuthZ{}, slog.Default())
	})
}

func TestNew_NilAuthZPanics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "detection operator.New: authz must not be nil", func() {
		New(fakeService{}, nil, slog.Default())
	})
}

func TestNew_NilLoggerFallsBackToDefault(t *testing.T) {
	t.Parallel()
	h := New(fakeService{}, allowAllAuthZ{}, nil)
	require.NotNil(t, h)
	assert.NotNil(t, h.logger)
}

// readErrorEnvelope decodes the JSON `{"error": "<code>"}` body the handler emits on 4xx / 5xx and returns the typed code so each
// test pins both the HTTP status AND the stable code a scripted client would dispatch on.
func readErrorEnvelope(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json",
		"4xx/5xx responses MUST carry application/json (server-rest-api JSON envelope spec)")
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	return parsed["error"]
}

// doGet + doPut centralise the http.NewRequestWithContext+Do pattern the noctx linter requires every test in this file to use.
// Each helper threads t.Context() so context propagation matches what the production handler middleware would see.
func doGet(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func doPut(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestHandleListHosts(t *testing.T) {
	t.Parallel()
	t.Run("authz deny returns no body from handler", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, denyAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts")
		defer resp.Body.Close()
		// HTTPGate emits the deny response itself; the handler returns immediately after seeing !ok. Status is 403 or similar
		// per HTTPGate's contract; this test only pins that the handler does NOT proceed past the gate (svc would panic if it did).
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("svc error returns 500 with internal code", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{listHosts: func(context.Context) ([]api.HostSummary, error) {
			return nil, errors.New("db down")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("nil hosts normalized to empty array", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{listHosts: func(context.Context) ([]api.HostSummary, error) { return nil, nil }}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "[]\n", string(body), "nil slice MUST serialize as [] not null to keep client TypeScript happy")
	})
}

func TestHandleProcessTree(t *testing.T) {
	t.Parallel()
	t.Run("authz deny short-circuits before svc", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, denyAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/tree")
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("svc error returns 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{buildTree: func(context.Context, string, api.TimeRange, int) ([]api.ProcessNode, error) {
			return nil, errors.New("query failed")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/tree")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("nil roots normalized to empty array under roots key", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{buildTree: func(context.Context, string, api.TimeRange, int) ([]api.ProcessNode, error) {
			return nil, nil
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/tree")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var parsed map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
		assert.NotNil(t, parsed["roots"], "roots field MUST be present")
	})

	t.Run("limit param above max is clamped", func(t *testing.T) {
		t.Parallel()
		var sawLimit int
		svc := fakeService{buildTree: func(_ context.Context, _ string, _ api.TimeRange, limit int) ([]api.ProcessNode, error) {
			sawLimit = limit
			return nil, nil
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/tree?limit=999999")
		_ = resp.Body.Close()
		assert.Equal(t, processTreeMaxLimit, sawLimit, "an absurd limit MUST be clamped to processTreeMaxLimit")
	})
}

func TestHandleProcessDetail(t *testing.T) {
	t.Parallel()
	t.Run("authz deny short-circuits before svc", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, denyAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/processes/1234")
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("svc error returns 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getProcessDetail: func(context.Context, string, int, int64) (*api.ProcessDetail, error) {
			return nil, errors.New("graph error")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/processes/1234")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("happy path returns the detail object", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getProcessDetail: func(context.Context, string, int, int64) (*api.ProcessDetail, error) {
			return &api.ProcessDetail{Process: api.Process{HostID: "host-a", PID: 1234}}, nil
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/hosts/host-a/processes/1234")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestHandleListAlerts(t *testing.T) {
	t.Parallel()
	t.Run("authz deny short-circuits before svc", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, denyAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts")
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("svc error returns 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{listAlerts: func(context.Context, api.AlertFilter) ([]api.Alert, error) {
			return nil, errors.New("alerts query failed")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("nil alerts normalized to empty array", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{listAlerts: func(context.Context, api.AlertFilter) ([]api.Alert, error) { return nil, nil }}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "[]\n", string(body))
	})
}

func TestHandleGetAlert(t *testing.T) {
	t.Parallel()
	t.Run("bad id returns 400 with invalid_alert_id", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/not-a-number")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, errInvalidAlertID, readErrorEnvelope(t, resp))
	})

	t.Run("authz deny short-circuits before svc", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, denyAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("not found returns 404 with not_found", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getAlert: func(context.Context, int64) (api.Alert, []string, error) {
			return api.Alert{}, nil, api.ErrAlertNotFound
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Equal(t, errNotFound, readErrorEnvelope(t, resp))
	})

	t.Run("svc error returns 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getAlert: func(context.Context, int64) (api.Alert, []string, error) {
			return api.Alert{}, nil, errors.New("db read failed")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("happy path includes event_ids", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getAlert: func(context.Context, int64) (api.Alert, []string, error) {
			return api.Alert{HostID: "host-a", RuleID: "r"}, []string{"evt-1", "evt-2"}, nil
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var parsed map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
		ids, ok := parsed["event_ids"].([]any)
		require.True(t, ok, "event_ids MUST be a JSON array")
		assert.Len(t, ids, 2)
	})

	// spec:server-detection-rules-engine/alert-evidence-is-self-contained/evidence-survives-event-archive-expiry
	t.Run("happy path includes self-contained event payloads", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) {
				return api.Alert{HostID: "host-a", RuleID: "r"}, []string{"evt-1"}, nil
			},
			getAlertEvidence: func(context.Context, int64) ([]api.Event, error) {
				return []api.Event{{EventID: "evt-1", HostID: "host-a", EventType: "network_connect", Payload: json.RawMessage(`{"pid":9}`)}}, nil
			},
		}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var parsed map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
		events, ok := parsed["events"].([]any)
		require.True(t, ok, "events MUST be a JSON array")
		require.Len(t, events, 1)
		assert.Equal(t, "network_connect", events[0].(map[string]any)["event_type"])
	})

	t.Run("evidence read error degrades to empty events, still serves the alert", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) {
				return api.Alert{HostID: "host-a", RuleID: "r"}, []string{"evt-1"}, nil
			},
			getAlertEvidence: func(context.Context, int64) ([]api.Event, error) {
				return nil, errors.New("evidence read failed")
			},
		}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doGet(t, srv, "/api/alerts/42")
		defer resp.Body.Close()
		// Evidence is best-effort: a failed payload read must not 500 the whole detail view that GetAlert already resolved.
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var parsed map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
		ids, ok := parsed["event_ids"].([]any)
		require.True(t, ok, "event_ids still served when evidence read fails")
		assert.Len(t, ids, 1)
		events, ok := parsed["events"].([]any)
		require.True(t, ok, "events MUST be a JSON array even on evidence read failure")
		assert.Empty(t, events, "evidence degrades to an empty array, not null or 500")
	})
}

func TestHandleUpdateAlertStatus(t *testing.T) {
	t.Parallel()
	t.Run("bad id returns invalid_alert_id", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/abc", `{"status":"acknowledged"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, errInvalidAlertID, readErrorEnvelope(t, resp))
	})

	t.Run("bad json body returns invalid_json", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{not valid`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		// testifylint flags this as encoded-compare because the constant name contains "JSON": false positive, the value
		// "invalid_json" is a plain typed error code (not a JSON document).
		//nolint:testifylint // encoded-compare false positive on constant name; values are plain strings.
		assert.Equal(t, errInvalidJSONBody, readErrorEnvelope(t, resp))
	})

	t.Run("body exceeding cap maps to invalid_json (MaxBytesReader)", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, allowAllAuthZ{})
		bigPayload := `{"status":"acknowledged","filler":"` + strings.Repeat("x", updateAlertStatusBodyCap+1) + `"}`
		resp := doPut(t, srv, "/api/alerts/42", bigPayload)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"oversized body MUST be rejected before reaching svc (Gemini's DoS-prevention requirement)")
	})

	t.Run("unknown status returns invalid_status", func(t *testing.T) {
		t.Parallel()
		srv := newOperatorServer(t, fakeService{}, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"banana"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, errInvalidStatus, readErrorEnvelope(t, resp))
	})

	t.Run("pre-gate not-found returns 404", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getAlert: func(context.Context, int64) (api.Alert, []string, error) {
			return api.Alert{}, nil, api.ErrAlertNotFound
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"acknowledged"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Equal(t, errNotFound, readErrorEnvelope(t, resp))
	})

	t.Run("pre-gate svc error returns 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{getAlert: func(context.Context, int64) (api.Alert, []string, error) {
			return api.Alert{}, nil, errors.New("db down")
		}}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"acknowledged"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("update returns ErrInvalidAlertTransition -> invalid_status_transition", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) {
				return api.Alert{Severity: "low"}, nil, nil
			},
			updateAlertStatus: func(context.Context, int64, api.AlertStatus, string) (api.Alert, error) {
				return api.Alert{}, api.ErrInvalidAlertTransition
			},
		}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"acknowledged"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, errInvalidStatusTrans, readErrorEnvelope(t, resp))
	})

	t.Run("update returns ErrInvalidUserUpdater -> invalid_user", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) { return api.Alert{}, nil, nil },
			updateAlertStatus: func(context.Context, int64, api.AlertStatus, string) (api.Alert, error) {
				return api.Alert{}, api.ErrInvalidUserUpdater
			},
		}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"resolved"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, errInvalidUser, readErrorEnvelope(t, resp))
	})

	t.Run("update returns generic error -> internal 500", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) { return api.Alert{}, nil, nil },
			updateAlertStatus: func(context.Context, int64, api.AlertStatus, string) (api.Alert, error) {
				return api.Alert{}, errors.New("db write failed")
			},
		}
		srv := newOperatorServer(t, svc, allowAllAuthZ{})
		resp := doPut(t, srv, "/api/alerts/42", `{"status":"open"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, errInternal, readErrorEnvelope(t, resp))
	})

	t.Run("happy path returns 204 and emits an audit row", func(t *testing.T) {
		t.Parallel()
		svc := fakeService{
			getAlert: func(context.Context, int64) (api.Alert, []string, error) {
				return api.Alert{Severity: "medium"}, nil, nil
			},
			updateAlertStatus: func(context.Context, int64, api.AlertStatus, string) (api.Alert, error) {
				return api.Alert{}, nil
			},
		}
		h := New(svc, allowAllAuthZ{}, slog.Default())
		audit := &recAudit{}
		h.SetAudit(audit)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		resp := doPut(t, srv, "/api/alerts/42", `{"status":"resolved"}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		require.Len(t, audit.events, 1, "successful status update MUST emit exactly one audit row")
		assert.Equal(t, identityapi.AuditAlertResolve, audit.events[0].Action)
		assert.Equal(t, "alert", audit.events[0].TargetType)
		assert.Equal(t, "42", audit.events[0].TargetID)
	})
}
