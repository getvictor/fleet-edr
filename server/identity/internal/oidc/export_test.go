package oidc

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// NewHandlerForTest builds a Handler with a custom IDPClient and the already-constructed Provisioner / sessions store. EXPORTED FOR
// TESTING ONLY (file is _test, never compiled into the production binary): the integration tests in oidc_test inject a fake IDPClient
// so the callback's happy path can be walked without a discovery server. Production code uses NewHandler.
// policy rides back with the client exactly as production's resolver returns it, so a test walks the same one-read path.
func NewHandlerForTest(
	idp IDPClient, policy Policy, prov *Provisioner, sess *sessions.Store,
	signingKey []byte, audit api.AuditRecorder, logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return NewHandlerForTestWithResolve(
		func(context.Context) (IDPClient, Policy, error) { return idp, policy, nil }, prov, sess, signingKey, audit, logger)
}

// NewHandlerForTestWithResolve is NewHandlerForTest with the resolve seam itself supplied, so a test can make the configuration move
// between the callback's reads the way an admin's save does. EXPORTED FOR TESTING ONLY.
func NewHandlerForTestWithResolve(
	resolve func(ctx context.Context) (IDPClient, Policy, error), prov *Provisioner, sess *sessions.Store,
	signingKey []byte, audit api.AuditRecorder, logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		resolve:     resolve,
		provisioner: prov,
		sessions:    sess,
		signingKey:  signingKey,
		stateTTL:    defaultStateTTL,
		audit:       audit,
		logger:      logger,
	}
}

// HandleLoginForTest invokes the unexported handleLogin so external
// tests can drive the route. Test-only.
func (h *Handler) HandleLoginForTest() func(http.ResponseWriter, *http.Request) {
	return h.handleLogin
}

// HandleCallbackForTest is the same affordance for the callback
// route. Test-only.
func (h *Handler) HandleCallbackForTest() func(http.ResponseWriter, *http.Request) {
	return h.handleCallback
}
