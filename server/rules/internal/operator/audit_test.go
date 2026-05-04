package operator

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// fakePolicyService stubs the operator handler's Service surface
// (PolicyService + Lister + Fanout). Each method has a closure so
// tests inject only the behaviour they need.
type fakePolicyService struct {
	get    func(ctx context.Context) (api.BlocklistPolicy, error)
	update func(ctx context.Context, req api.UpdateRequest) (api.BlocklistPolicy, error)
	list   func() []api.RuleMetadata
	fanout func(ctx context.Context, p api.BlocklistPolicy) (int, int, error)
}

func (f fakePolicyService) Get(ctx context.Context) (api.BlocklistPolicy, error) {
	if f.get == nil {
		return api.BlocklistPolicy{}, nil
	}
	return f.get(ctx)
}
func (f fakePolicyService) Update(ctx context.Context, req api.UpdateRequest) (api.BlocklistPolicy, error) {
	if f.update == nil {
		panic("fake.Update not set")
	}
	return f.update(ctx, req)
}
func (f fakePolicyService) List() []api.RuleMetadata {
	if f.list == nil {
		return nil
	}
	return f.list()
}
func (f fakePolicyService) Fanout(ctx context.Context, p api.BlocklistPolicy) (int, int, error) {
	if f.fanout == nil {
		return 0, 0, nil
	}
	return f.fanout(ctx, p)
}
func (f fakePolicyService) ActiveCommandPayload(context.Context) (stdjson.RawMessage, int64, bool, error) {
	panic("not used")
}

type captureRecorder struct {
	last   identityapi.AuditEvent
	called bool
}

func (c *captureRecorder) Record(_ context.Context, e identityapi.AuditEvent) error {
	c.called = true
	c.last = e
	return nil
}

// allowAllAuthZ satisfies identityapi.AuthZ as an unconditional grant.
// This package's tests focus on policy + audit semantics, not the
// chokepoint's role matrix (covered exhaustively in
// server/identity/internal/authz/engine_test.go).
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// A successful policy update emits one audit row carrying the operator-
// supplied actor + reason in the payload, alongside the new version,
// path/hash counts, and fan-out stats. Reviewers later asking
// "who pushed v3 of the blocklist and why" land on this row.
func TestHandler_PolicyUpdate_EmitsAudit(t *testing.T) {
	svc := fakePolicyService{
		update: func(_ context.Context, _ api.UpdateRequest) (api.BlocklistPolicy, error) {
			return api.BlocklistPolicy{
				Name:    api.DefaultPolicyName,
				Version: 7,
				Blocklist: api.Blocklist{
					Paths:  []string{"/usr/local/bin/x"},
					Hashes: []string{},
				},
			}, nil
		},
		fanout: func(_ context.Context, _ api.BlocklistPolicy) (int, int, error) {
			return 3, 0, nil
		},
	}
	rec := &captureRecorder{}
	h := New(svc, allowAllAuthZ{}, nil)
	h.SetAudit(rec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := stdjson.Marshal(map[string]any{
		"paths":  []string{"/usr/local/bin/x"},
		"hashes": []string{},
		"actor":  "victor@example",
		"reason": "incident-2026-Q2",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, rec.called)
	assert.Equal(t, identityapi.AuditPolicyUpdate, rec.last.Action)
	assert.Equal(t, "policy", rec.last.TargetType)
	assert.Equal(t, api.DefaultPolicyName, rec.last.TargetID)
	assert.Equal(t, "victor@example", rec.last.Payload["actor"])
	assert.Equal(t, "incident-2026-Q2", rec.last.Payload["reason"])
	assert.EqualValues(t, 7, rec.last.Payload["version"])
	assert.EqualValues(t, 1, rec.last.Payload["path_count"])
	assert.EqualValues(t, 0, rec.last.Payload["hash_count"])
	assert.EqualValues(t, 3, rec.last.Payload["fanout_hosts"])
	assert.EqualValues(t, 0, rec.last.Payload["fanout_failed"])
}

// Nil recorder is the documented "audit-disabled" mode; the policy
// update must still apply and return 200 without panicking.
func TestHandler_PolicyUpdate_NilAuditOK(t *testing.T) {
	svc := fakePolicyService{
		update: func(_ context.Context, _ api.UpdateRequest) (api.BlocklistPolicy, error) {
			return api.BlocklistPolicy{Name: api.DefaultPolicyName, Version: 1}, nil
		},
	}
	h := New(svc, allowAllAuthZ{}, nil)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := stdjson.Marshal(map[string]any{"actor": "v", "reason": "r"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+"/api/policy", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
