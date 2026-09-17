package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// serveWithActor runs the operator routes with an actor on the request context, as the authenticated middleware does.
func serveWithActor(t *testing.T, h *Handler, actor identityapi.PrincipalRef) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if actor.ID == "" {
			mux.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r.WithContext(identityapi.WithActor(r.Context(), &identityapi.Actor{Principal: actor})))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// post sends one request and returns its status. The body is read and closed here because no caller of this helper reads it; the
// tests assert on the audit entries the write committed, not on the response.
func post(t *testing.T, srv *httptest.Server, path string, body any) int {
	t.Helper()
	var rdr *bytes.Reader
	if body == nil {
		rdr = bytes.NewReader(nil)
	} else {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, rdr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// spec:server-admin-surface/operator-actions-commit-their-audit-entry/an-issued-command-commits-its-audit-entry
//
// Issuing a command records one row naming the host it was sent to, the acting principal, the address they acted from, and the
// command's type and id, so a customer asking "who issued kill_process for host X" has an answer. The entry is built inside the
// write, which is what commits it with the command rather than after it (issue #1070).
func TestHandler_CommandIssue_CommitsItsAuditEntry(t *testing.T) {
	t.Parallel()
	var entries []identityapi.AuditEvent
	svc := fakeService{
		insert:  func(context.Context, string, string, []byte) (int64, error) { return 99, nil },
		entries: &entries,
	}
	actor := identityapi.PrincipalRef{ID: "usr_7", Type: identityapi.PrincipalUser, Label: "ada"}
	srv := serveWithActor(t, New(svc, allowAllAuthZ{}, nil), actor)

	require.Equal(t, http.StatusCreated, post(t, srv, "/api/commands", map[string]any{
		"host_id": "H-1", "command_type": "kill_process", "payload": map[string]any{"pid": 1234},
	}))

	require.Len(t, entries, 1)
	assert.Equal(t, identityapi.AuditCommandIssue, entries[0].Action)
	assert.Equal(t, actor, entries[0].Actor)
	assert.Equal(t, "host", entries[0].TargetType)
	assert.Equal(t, "H-1", entries[0].TargetID)
	assert.NotEmpty(t, entries[0].RemoteAddr, "the address the operator acted from")
	assert.Equal(t, "kill_process", entries[0].Payload["command_type"])
	assert.EqualValues(t, 99, entries[0].Payload["command_id"], "the id the write reported, not one guessed beforehand")
}

// spec:server-admin-surface/operator-actions-commit-their-audit-entry/a-withdrawn-command-is-audited-as-a-withdrawal
//
// Issue #1085: both routes shared one helper that named command.issue, so withdrawing a command recorded a row saying it was issued.
// The two rows are otherwise identical (same host, same command_type, same command_id), so nothing in the trail told them apart and a
// count of issued response actions over-reported by every withdrawal.
func TestHandler_CommandCancel_IsAuditedAsAWithdrawal(t *testing.T) {
	t.Parallel()
	var entries []identityapi.AuditEvent
	svc := fakeService{
		get: func(_ context.Context, id int64) (api.Command, error) {
			return api.Command{ID: id, HostID: "H-1", CommandType: "kill_process", Status: api.StatusPending}, nil
		},
		updateStatus: func(context.Context, api.UpdateStatusRequest) error { return nil },
		entries:      &entries,
	}
	actor := identityapi.PrincipalRef{ID: "usr_7", Type: identityapi.PrincipalUser, Label: "ada"}
	srv := serveWithActor(t, New(svc, allowAllAuthZ{}, nil), actor)

	require.Equal(t, http.StatusOK, post(t, srv, "/api/commands/42/cancel", nil))

	require.Len(t, entries, 1)
	assert.Equal(t, identityapi.AuditCommandCancel, entries[0].Action,
		"a withdrawal is not an issuance; recording both as command.issue is what issue #1085 reported")
	assert.Equal(t, "H-1", entries[0].TargetID)
	assert.Equal(t, "kill_process", entries[0].Payload["command_type"])
	assert.EqualValues(t, 42, entries[0].Payload["command_id"])
}

// An action that never commits records nothing: the audit trail says what happened, not what was attempted. The authorization
// chokepoint records the attempt separately.
func TestHandler_AFailedActionCommitsNoAuditEntry(t *testing.T) {
	t.Parallel()
	t.Run("insert refused", func(t *testing.T) {
		t.Parallel()
		var entries []identityapi.AuditEvent
		svc := fakeService{
			insert:  func(context.Context, string, string, []byte) (int64, error) { return 0, api.ErrInvalidInsertRequest },
			entries: &entries,
		}
		srv := serveWithActor(t, New(svc, allowAllAuthZ{}, nil), identityapi.PrincipalRef{ID: "usr_7"})

		body := map[string]any{"host_id": "H-1", "command_type": "kill_process"}
		assert.Equal(t, http.StatusBadRequest, post(t, srv, "/api/commands", body))
		assert.Empty(t, entries)
	})

	t.Run("cancel refused", func(t *testing.T) {
		t.Parallel()
		var entries []identityapi.AuditEvent
		svc := fakeService{
			get: func(_ context.Context, id int64) (api.Command, error) {
				return api.Command{ID: id, HostID: "H-1", CommandType: "kill_process", Status: api.StatusAcked}, nil
			},
			updateStatus: func(context.Context, api.UpdateStatusRequest) error { return api.ErrInvalidStatusTransition },
			entries:      &entries,
		}
		srv := serveWithActor(t, New(svc, allowAllAuthZ{}, nil), identityapi.PrincipalRef{ID: "usr_7"})

		assert.Equal(t, http.StatusConflict, post(t, srv, "/api/commands/42/cancel", nil))
		assert.Empty(t, entries)
	})
}
