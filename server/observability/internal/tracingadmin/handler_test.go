package tracingadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/observability/internal/tracingconfig"
)

type fakeStore struct {
	cur       *tracing.Settings
	version   int64
	getErr    error
	updErr    error
	updated   *tracing.Settings
	updatedBy *int64
	gotExpVer int64
}

func (f *fakeStore) Get(context.Context) (*tracing.Settings, int64, error) {
	if f.getErr != nil {
		return nil, 0, f.getErr
	}
	cur := f.cur
	if cur == nil {
		cur = &tracing.Settings{}
	}
	cp := *cur
	return &cp, f.version, nil
}

func (f *fakeStore) Update(_ context.Context, s tracing.Settings, expectedVersion int64, by *int64) error {
	f.gotExpVer = expectedVersion
	if f.updErr != nil {
		return f.updErr
	}
	cp := s
	f.updated = &cp
	f.updatedBy = by
	f.cur = &cp
	return nil
}

type allowAuthZ struct{}

func (allowAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

type denyAuthZ struct{}

func (denyAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: false, Reason: "no_matching_rule"}, nil
}

type captureAudit struct{ events []api.AuditEvent }

func (c *captureAudit) Record(_ context.Context, e api.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

func patchReq(t *testing.T, rawBody string, withActor bool) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/settings/tracing", bytes.NewReader([]byte(rawBody)))
	if withActor {
		r = r.WithContext(api.WithActor(r.Context(), &api.Actor{UserID: 7, AuthMethod: "oidc"}))
	}
	return r
}

func patchJSON(t *testing.T, body any, withActor bool) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return patchReq(t, string(b), withActor)
}

func TestHandleGet_returnsCurrentSettings(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.02, StandardRatio: 0.2, ForceFull: true}, version: 3}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)

	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/tracing", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var resp settingsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.InDelta(t, 0.02, resp.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.2, resp.StandardRatio, 1e-9)
	assert.True(t, resp.ForceFull)
}

func TestHandleGet_deniedReturns403(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, denyAuthZ{}, &captureAudit{}, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/tracing", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleGet_storeErrorReturns500(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{getErr: errors.New("db down")}, allowAuthZ{}, &captureAudit{}, nil)
	w := httptest.NewRecorder()
	h.handleGet(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/tracing", nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// spec:observability-instrumentation/operators-adjust-sampler-settings-through-an-authenticated-admin-endpoint/an-administrator-updates-the-ratios
func TestHandleUpdate_adminUpdatesRatios(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 5}
	audit := &captureAudit{}
	h := NewHandler(store, allowAuthZ{}, audit, nil)

	hv, std := 0.05, 0.25
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv, StandardRatio: &std}, true))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.updated)
	assert.InDelta(t, 0.05, store.updated.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.25, store.updated.StandardRatio, 1e-9)
	assert.Equal(t, int64(5), store.gotExpVer, "Update must carry the version read by Get for OCC")
	require.NotNil(t, store.updatedBy)
	assert.Equal(t, int64(7), *store.updatedBy)
	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditAction("tracing.settings.updated"), audit.events[0].Action)
}

func TestHandleUpdate_partialKeepsStoredFields(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1, ForceFull: false}, version: 1}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)

	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, `{"force_full":true}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.updated)
	assert.InDelta(t, 0.01, store.updated.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.1, store.updated.StandardRatio, 1e-9)
	assert.True(t, store.updated.ForceFull)
}

// spec:observability-instrumentation/operators-adjust-sampler-settings-through-an-authenticated-admin-endpoint/update-with-an-out-of-range-ratio-is-rejected
func TestHandleUpdate_outOfRangeRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hv   float64
		std  float64
	}{
		{"high-volume above 1", 1.5, 0.1},
		{"high-volume below 0", -0.1, 0.1},
		{"standard above 1", 0.1, 2.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1}
			h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &tc.hv, StandardRatio: &tc.std}, true))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Nil(t, store.updated, "no write on validation failure")
		})
	}
}

// spec:observability-instrumentation/operators-adjust-sampler-settings-through-an-authenticated-admin-endpoint/an-operator-without-the-grant-is-denied
func TestHandleUpdate_deniedReturns403AndDoesNotWrite(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1}
	h := NewHandler(store, denyAuthZ{}, &captureAudit{}, nil)

	hv := 0.9
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv}, true))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, store.updated)
}

func TestHandleUpdate_versionConflictReturns409(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1, updErr: tracingconfig.ErrVersionConflict}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)

	hv := 0.5
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv}, true))
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandleUpdate_storeUpdateErrorReturns500(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1, updErr: errors.New("db down")}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	hv := 0.5
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv}, true))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleUpdate_storeReadErrorReturns500(t *testing.T) {
	t.Parallel()
	store := &fakeStore{getErr: errors.New("db down")}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	hv := 0.5
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv}, true))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleUpdate_unknownFieldRejected(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	w := httptest.NewRecorder()
	// A misspelled key must be a 400, not a silent 200 no-op.
	h.handleUpdate(w, patchReq(t, `{"forcefull":true}`, true))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, store.updated)
}

func TestHandleUpdate_trailingJSONRejected(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, `{"force_full":true}{"force_full":false}`, true))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, store.updated)
}

func TestHandleUpdate_invalidJSONReturns400(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, allowAuthZ{}, &captureAudit{}, nil)
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, "{not json", true))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleUpdate_noActorIsInternalError(t *testing.T) {
	t.Parallel()
	// allow authz but no actor on ctx: a wiring bug, surfaced as 500 rather than a nil-deref.
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}, version: 1}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	hv := 0.5
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchJSON(t, updateRequest{HighVolumeRatio: &hv}, false))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Nil(t, store.updated)
}

func TestNewHandler_panicsWithoutRequiredDeps(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { NewHandler(nil, allowAuthZ{}, &captureAudit{}, nil) })
	assert.Panics(t, func() { NewHandler(&fakeStore{}, nil, &captureAudit{}, nil) })
}
