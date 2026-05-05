package oidc

import (
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// NewHandlerForTest builds a Handler with a custom IDPClient and the
// already-constructed Provisioner / sessions store. EXPORTED FOR
// TESTING ONLY (file is _test, never compiled into the production
// binary): the integration tests in oidc_test inject a fake
// IDPClient so the callback's happy path can be walked without a
// discovery server. Production code uses NewHandler.
func NewHandlerForTest(
	idp IDPClient, prov *Provisioner, sess *sessions.Store,
	signingKey []byte, audit api.AuditRecorder, logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		client:       idp,
		provisioner:  prov,
		sessions:     sess,
		signingKey:   signingKey,
		stateTTL:     defaultStateTTL,
		cookieSecure: false,
		audit:        audit,
		logger:       logger,
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
