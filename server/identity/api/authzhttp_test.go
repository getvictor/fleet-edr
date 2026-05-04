package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

// stubAuthZ is the configurable AuthZ for the helpers' direct tests.
// Each case pins the (decision, error) the engine returns; the helper
// is then exercised against the resulting HTTP response so the wire
// shape every operator handler depends on stays locked.
type stubAuthZ struct {
	decision api.Decision
	err      error
	called   int
}

func (s *stubAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	s.called++
	return s.decision, s.err
}

// HTTPGate's allow path returns true and writes nothing to the
// ResponseWriter — the caller is expected to continue producing the
// real response. A non-zero default status code (200) appears only
// because httptest.NewRecorder defaults that way; the helper itself
// emits no headers/body.
func TestHTTPGate_Allow(t *testing.T) {
	az := &stubAuthZ{decision: api.Decision{Allow: true, Reason: "granted"}}
	w := httptest.NewRecorder()

	ok := api.HTTPGate(t.Context(), w, az, slog.Default(),
		api.ActionAuditRead, api.Resource{TenantID: "default", Type: "audit"})

	assert.True(t, ok)
	assert.Equal(t, 1, az.called)
	assert.Empty(t, w.Body.String(), "allow path must not write a body; the handler does")
	assert.Empty(t, w.Header().Get(api.AuthzReasonHeader),
		"allow path must not set the deny-reason header")
}

// Deny: 403 + reason on header + JSON `{"error":"forbidden"}` body.
// The header is the operator UI's signal to surface "forbidden — your
// role does not allow this action" without parsing a body shape that
// already varies by failure class.
func TestHTTPGate_Deny(t *testing.T) {
	az := &stubAuthZ{decision: api.Decision{Allow: false, Reason: "no_matching_rule"}}
	w := httptest.NewRecorder()

	ok := api.HTTPGate(t.Context(), w, az, slog.Default(),
		api.ActionPolicyUpdate, api.Resource{TenantID: "default", Type: "policy"})

	assert.False(t, ok)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "no_matching_rule", w.Header().Get(api.AuthzReasonHeader))

	body, _ := io.ReadAll(w.Body)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "forbidden", got["error"])
}

// EngineError: 503 (transient) + JSON `{"error":"authz_unavailable"}`.
// 503 (not 500) so the UI's retry-on-5xx semantics fire instead of
// the 401-on-403 redirect-to-login that would lose the operator's
// in-progress work.
func TestHTTPGate_EngineError(t *testing.T) {
	az := &stubAuthZ{err: errors.New("opa exploded")}
	w := httptest.NewRecorder()

	ok := api.HTTPGate(t.Context(), w, az, slog.Default(),
		api.ActionHostIsolate, api.Resource{TenantID: "default", Type: "host", ID: "h-1"})

	assert.False(t, ok)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	body, _ := io.ReadAll(w.Body)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "authz_unavailable", got["error"])
	assert.Empty(t, w.Header().Get(api.AuthzReasonHeader),
		"engine error is infrastructure failure, not a policy decision; reason header would be misleading")
}

// ActorTenantID returns the actor's tenant_id when one is on ctx —
// the standard middleware-pinned shape every privileged handler reads
// before building a Resource.
func TestActorTenantID_PresentActor(t *testing.T) {
	ctx := api.WithActor(context.Background(), &api.Actor{
		UserID: 1, TenantID: "tenant-a", AuthMethod: "local_password",
	})
	assert.Equal(t, "tenant-a", api.ActorTenantID(ctx))
}

// Without an actor on ctx the helper returns "" so the chokepoint can
// short-circuit on resource_tenant_missing AND audit the regression;
// returning a non-empty default would mask the missing-actor case.
func TestActorTenantID_NoActor(t *testing.T) {
	assert.Empty(t, api.ActorTenantID(context.Background()))
}
