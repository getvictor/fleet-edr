package tracingadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/identity/api"
)

type fakeStore struct {
	cur       *tracing.Settings
	getErr    error
	updErr    error
	updated   *tracing.Settings
	updatedBy *int64
}

func (f *fakeStore) GetTraceSamplerSettings(context.Context) (*tracing.Settings, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.cur == nil {
		return &tracing.Settings{}, nil
	}
	cp := *f.cur
	return &cp, nil
}

func (f *fakeStore) Update(_ context.Context, s tracing.Settings, by *int64) error {
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

func patchReq(t *testing.T, body any, withActor bool) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/settings/tracing", bytes.NewReader(b))
	if withActor {
		r = r.WithContext(api.WithActor(r.Context(), &api.Actor{UserID: 7, AuthMethod: "oidc"}))
	}
	return r
}

func TestHandleGet_returnsCurrentSettings(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.02, StandardRatio: 0.2, ForceFull: true}}
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

// spec:observability-instrumentation/operators-adjust-sampler-settings-through-an-authenticated-admin-endpoint/an-administrator-updates-the-ratios
func TestHandleUpdate_superAdminUpdatesRatios(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}}
	audit := &captureAudit{}
	h := NewHandler(store, allowAuthZ{}, audit, nil)

	hv, std := 0.05, 0.25
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, updateRequest{HighVolumeRatio: &hv, StandardRatio: &std}, true))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.updated)
	assert.InDelta(t, 0.05, store.updated.HighVolumeRatio, 1e-9)
	assert.InDelta(t, 0.25, store.updated.StandardRatio, 1e-9)
	require.NotNil(t, store.updatedBy)
	assert.Equal(t, int64(7), *store.updatedBy)
	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditAction("tracing.settings.updated"), audit.events[0].Action)

	var resp settingsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.InDelta(t, 0.05, resp.HighVolumeRatio, 1e-9)
}

func TestHandleUpdate_partialKeepsStoredFields(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1, ForceFull: false}}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)

	forceFull := true
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, updateRequest{ForceFull: &forceFull}, true))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.updated)
	// Ratios omitted from the PATCH must be preserved.
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
			store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}}
			h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
			w := httptest.NewRecorder()
			h.handleUpdate(w, patchReq(t, updateRequest{HighVolumeRatio: &tc.hv, StandardRatio: &tc.std}, true))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Nil(t, store.updated, "no write on validation failure")
		})
	}
}

// spec:observability-instrumentation/operators-adjust-sampler-settings-through-an-authenticated-admin-endpoint/an-operator-without-the-grant-is-denied
func TestHandleUpdate_deniedReturns403AndDoesNotWrite(t *testing.T) {
	t.Parallel()
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}}
	h := NewHandler(store, denyAuthZ{}, &captureAudit{}, nil)

	hv := 0.9
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, updateRequest{HighVolumeRatio: &hv}, true))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, store.updated)
}

func TestHandleUpdate_invalidJSONReturns400(t *testing.T) {
	t.Parallel()
	h := NewHandler(&fakeStore{}, allowAuthZ{}, &captureAudit{}, nil)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/settings/tracing", bytes.NewReader([]byte("{not json")))
	r = r.WithContext(api.WithActor(r.Context(), &api.Actor{UserID: 7}))
	w := httptest.NewRecorder()
	h.handleUpdate(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleUpdate_noActorIsInternalError(t *testing.T) {
	t.Parallel()
	// allow authz but no actor on ctx: a wiring bug, surfaced as 500 rather than a nil-deref.
	store := &fakeStore{cur: &tracing.Settings{HighVolumeRatio: 0.01, StandardRatio: 0.1}}
	h := NewHandler(store, allowAuthZ{}, &captureAudit{}, nil)
	hv := 0.5
	w := httptest.NewRecorder()
	h.handleUpdate(w, patchReq(t, updateRequest{HighVolumeRatio: &hv}, false))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Nil(t, store.updated)
}

func TestNewHandler_panicsWithoutRequiredDeps(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { NewHandler(nil, allowAuthZ{}, nil, nil) })
	assert.Panics(t, func() { NewHandler(&fakeStore{}, nil, nil, nil) })
}
