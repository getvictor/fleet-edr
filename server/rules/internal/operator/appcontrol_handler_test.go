package operator

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// quietLogger discards handler log output so the error-branch tests (which all log) don't spam the test runner.
func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// errReader is an io.Reader that always fails, so readAppControlBody's io.ReadAll error branch can be exercised: a real HTTP
// client can't easily produce a server-side body-read failure, so the request body is swapped for this instead.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// decodeErrResponse pulls the typed {error,message} envelope writeAppControlErr emits so the tests can assert the exact wire code.
func decodeErrResponse(t *testing.T, body []byte) (code, message string) {
	t.Helper()
	var env struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	return env.Error, env.Message
}

// TestReadAppControlBody covers both arms of the extracted readAppControlBody helper: a clean read returns the bytes + ok, and a
// failing body read maps to the typed 400 read_body response with ok=false.
func TestReadAppControlBody(t *testing.T) {
	t.Parallel()
	h := &AppControlHandler{logger: quietLogger()}

	t.Run("clean read returns the body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(`{"reason":"r"}`))
		rec := httptest.NewRecorder()
		body, ok := h.readAppControlBody(req.Context(), rec, req, applicationControlReadBodyLimit)
		require.True(t, ok)
		assert.JSONEq(t, `{"reason":"r"}`, string(body))
		assert.Equal(t, http.StatusOK, rec.Code, "no error response is written on the happy path")
	})

	t.Run("body read error maps to 400 read_body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
		req.Body = io.NopCloser(errReader{})
		rec := httptest.NewRecorder()
		body, ok := h.readAppControlBody(req.Context(), rec, req, applicationControlReadBodyLimit)
		require.False(t, ok)
		assert.Nil(t, body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, errCodeReadBody, code)
	})
}

// spec:server-admin-surface/operator-mutation-endpoints-reject-oversize-request-bodies/oversize-application-control-mutation-body-is-rejected
//
// TestReadAppControlBody_SizeLimit pins the 413 gate: readAppControlBody reads one byte past the per-route cap so an over-limit body
// is rejected with the typed body_too_large 413 rather than silently truncated (a truncated payload would surface as a misleading
// invalid_json 400 or a partial-but-valid mutation). A body exactly at the cap still reads clean, on both the per-rule (16 KiB) and
// bulk-upsert (256 KiB) caps.
func TestReadAppControlBody_SizeLimit(t *testing.T) {
	t.Parallel()
	h := &AppControlHandler{logger: quietLogger()}

	cases := []struct {
		name       string
		limit      int64
		size       int
		wantOK     bool
		wantStatus int
	}{
		{"per-rule cap: at limit reads clean", applicationControlReadBodyLimit, applicationControlReadBodyLimit, true, http.StatusOK},
		{"per-rule cap: over limit is 413", applicationControlReadBodyLimit, applicationControlReadBodyLimit + 1, false, http.StatusRequestEntityTooLarge},
		{"bulk cap: at limit reads clean", bulkUpsertReadBodyLimit, bulkUpsertReadBodyLimit, true, http.StatusOK},
		{"bulk cap: over limit is 413", bulkUpsertReadBodyLimit, bulkUpsertReadBodyLimit + 1, false, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", tc.size)))
			rec := httptest.NewRecorder()
			body, ok := h.readAppControlBody(req.Context(), rec, req, tc.limit)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Len(t, body, tc.size)
				assert.Equal(t, http.StatusOK, rec.Code, "no error response is written at or below the cap")
				return
			}
			assert.Nil(t, body)
			assert.Equal(t, tc.wantStatus, rec.Code)
			code, msg := decodeErrResponse(t, rec.Body.Bytes())
			assert.Equal(t, errCodeBodyTooLarge, code)
			assert.Equal(t, errMsgBodyTooLarge, msg)
		})
	}
}

// TestActorOrInternalError covers the extracted actorOrInternalError helper: an authenticated actor is returned as-is, while an
// absent actor (a session-middleware wiring bug, not a user error) logs and maps to a 500.
func TestActorOrInternalError(t *testing.T) {
	t.Parallel()
	h := &AppControlHandler{logger: quietLogger()}

	t.Run("actor on context is returned", func(t *testing.T) {
		t.Parallel()
		want := &identityapi.Actor{Principal: identityapi.UserPrincipal(7, "")}
		ctx := identityapi.WithActor(t.Context(), want)
		rec := httptest.NewRecorder()
		got, ok := h.actorOrInternalError(ctx, rec)
		require.True(t, ok)
		assert.Same(t, want, got)
		assert.Equal(t, http.StatusOK, rec.Code, "no error response is written when an actor is present")
	})

	t.Run("missing actor maps to 500 internal", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		got, ok := h.actorOrInternalError(t.Context(), rec)
		require.False(t, ok)
		assert.Nil(t, got)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, internalErrorCode, code)
	})
}

// TestDecodeAppControlBody covers the generic decode helper: valid JSON populates dst and returns true; invalid JSON maps to the
// typed 400 invalid_json response and returns false.
func TestDecodeAppControlBody(t *testing.T) {
	t.Parallel()

	t.Run("valid json populates dst", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst createPolicyRequest
		ok := decodeAppControlBody(t.Context(), quietLogger(), rec, []byte(`{"name":"P","reason":"r"}`), &dst)
		require.True(t, ok)
		assert.Equal(t, "P", dst.Name)
		assert.Equal(t, "r", dst.Reason)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("invalid json maps to 400 invalid_json", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst createPolicyRequest
		ok := decodeAppControlBody(t.Context(), quietLogger(), rec, []byte(`{not json`), &dst)
		require.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, msg := decodeErrResponse(t, rec.Body.Bytes())
		// errCodeInvalidJSON / errMsgInvalidJSON are plain typed strings ("application_control.invalid_json", "invalid json"), not
		// JSON documents, so testifylint's encoded-compare false-positives on the "JSON" in the constant name; JSONEq would fail.
		assert.Equal(t, errCodeInvalidJSON, code) //nolint:testifylint // encoded-compare false positive on JSON-named constant
		assert.Equal(t, errMsgInvalidJSON, msg)   //nolint:testifylint // encoded-compare false positive on JSON-named constant
	})
}

// TestDecodeAppControlBodyIfPresent covers the DELETE-route variant. The load-bearing case is the whitespace-only body: it must be
// normalized to empty (dst left at its zero value, no 400) so the downstream reason-required validation fires instead of a
// misleading invalid_json. A non-empty malformed body still maps to 400; a valid body decodes like the base helper.
func TestDecodeAppControlBodyIfPresent(t *testing.T) {
	t.Parallel()

	t.Run("whitespace-only body is normalized to empty, not rejected", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst deleteRuleRequest
		ok := decodeAppControlBodyIfPresent(t.Context(), quietLogger(), rec, []byte("  \n\t "), &dst)
		require.True(t, ok, "a whitespace-only body must not be rejected as invalid_json")
		assert.Equal(t, deleteRuleRequest{}, dst, "dst is left at its zero value so reason-required validation fires downstream")
		assert.Equal(t, http.StatusOK, rec.Code, "no error response is written for a whitespace body")
	})

	t.Run("empty body is treated as absent", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst deleteRuleRequest
		ok := decodeAppControlBodyIfPresent(t.Context(), quietLogger(), rec, nil, &dst)
		require.True(t, ok)
		assert.Equal(t, deleteRuleRequest{}, dst)
	})

	t.Run("valid non-empty body decodes", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst deleteRuleRequest
		ok := decodeAppControlBodyIfPresent(t.Context(), quietLogger(), rec, []byte(`{"reason":"cleanup"}`), &dst)
		require.True(t, ok)
		assert.Equal(t, "cleanup", dst.Reason)
	})

	t.Run("non-empty malformed body maps to 400 invalid_json", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		var dst deleteRuleRequest
		ok := decodeAppControlBodyIfPresent(t.Context(), quietLogger(), rec, []byte(`{"reason":`), &dst)
		require.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		// errCodeInvalidJSON is a plain typed error code, not a JSON document: encoded-compare false-positives on the constant name.
		assert.Equal(t, errCodeInvalidJSON, code) //nolint:testifylint // encoded-compare false positive on JSON-named constant
	})
}

// TestActorIdentifierFromContext pins the stable created_by / updated_by tag: the acting principal's id when an actor is present,
// and empty when none is (so the store-level required-actor gate produces a typed 400 rather than the handler short-circuiting).
func TestActorIdentifierFromContext(t *testing.T) {
	t.Parallel()

	t.Run("empty when no actor on context", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, actorIdentifierFromContext(t.Context()))
	})

	t.Run("returns the principal id for a user actor", func(t *testing.T) {
		t.Parallel()
		ctx := identityapi.WithActor(t.Context(), &identityapi.Actor{Principal: identityapi.UserPrincipal(42, "a@b.co")})
		assert.Equal(t, "usr_42", actorIdentifierFromContext(ctx))
	})

	t.Run("returns the principal id for a service-account actor", func(t *testing.T) {
		t.Parallel()
		ctx := identityapi.WithActor(t.Context(), &identityapi.Actor{Principal: identityapi.ServiceAccountPrincipal(3, "ci")})
		assert.Equal(t, "svc_3", actorIdentifierFromContext(ctx))
	})
}

// TestMutationHandlerEarlyExits drives the mutation handlers through their extracted-helper failure branches end to end (allow-all
// authz, no service call reached). Each case pins that the handler surfaces the helper's typed error and returns before touching
// the service, so svc is left nil deliberately: a regression that reordered a service call ahead of these guards would panic.
func TestMutationHandlerEarlyExits(t *testing.T) {
	t.Parallel()
	h := &AppControlHandler{authz: allowAllAuthZ{}, logger: quietLogger()}

	t.Run("create rule: invalid json is 400 invalid_json", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/app-control/policies/1/rules", strings.NewReader("{bad"))
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		h.handleCreateRule(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		// errCodeInvalidJSON is a plain typed error code, not a JSON document: encoded-compare false-positives on the constant name.
		assert.Equal(t, errCodeInvalidJSON, code) //nolint:testifylint // encoded-compare false positive on JSON-named constant
	})

	t.Run("create rule: valid body but no actor is 500", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/app-control/policies/1/rules",
			strings.NewReader(`{"rule_type":"BINARY","identifier":"/bin/x","reason":"r"}`))
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		h.handleCreateRule(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, internalErrorCode, code)
	})

	t.Run("create rule: body read error is 400 read_body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/app-control/policies/1/rules", nil)
		req.Body = io.NopCloser(errReader{})
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		h.handleCreateRule(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, errCodeReadBody, code)
	})

	t.Run("create rule: bad policy id is 400 invalid_policy_id", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/app-control/policies/0/rules", strings.NewReader("{}"))
		req.SetPathValue("id", "0") // non-positive -> parsePolicyID rejects
		rec := httptest.NewRecorder()
		h.handleCreateRule(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, errCodeInvalidPolicyID, code)
	})

	t.Run("delete rule: whitespace body is normalized then 500 on missing actor", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/app-control/rules/1", strings.NewReader("  \n  "))
		req.SetPathValue("id", "1")
		rec := httptest.NewRecorder()
		h.handleDeleteRule(rec, req)
		// A whitespace body must NOT 400 as invalid_json; it normalizes to empty and the flow proceeds to the actor gate, which
		// (no actor on this synthetic request) returns 500. This pins the decodeAppControlBodyIfPresent normalization branch.
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		code, _ := decodeErrResponse(t, rec.Body.Bytes())
		assert.Equal(t, internalErrorCode, code)
	})
}
