// Package token serves the agent-facing token refresh endpoint: POST /api/token/refresh.
//
// It is mounted behind the host-token middleware, so by the time the handler runs the request is already authenticated and the host_id
// is pinned on the context. The handler mints a fresh self-validating token for that host and returns it, letting a live agent renew
// before its current token expires without re-enrolling. A revoked or unknown host gets 401, which drives the agent's re-enroll path.
package token

import (
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// Handler serves POST /api/token/refresh. It implements http.Handler so cmd/main can mount it inside the host-token-protected mux,
// reusing the same middleware that authenticates every other agent route.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New builds a refresh handler. Panics if svc is nil (a wiring bug).
func New(svc api.Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("token.New: api.Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.svc.RefreshToken(ctx)
	if errors.Is(err, api.ErrInvalidToken) {
		// Host unknown or revoked: same 401 the middleware would emit, so the agent's existing re-enroll-on-401 path recovers it.
		httpserver.WriteAuthFailure(ctx, w, h.logger, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "token refresh", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.String(attrkeys.HostID, res.HostID))
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, res)
}
