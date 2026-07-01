package status

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// maxStatusBodyBytes caps the check-in body. The request is authenticated, but the cap still bounds a buggy or hostile agent: the real
// payload is a few hundred bytes for the two extensions, and 16 KiB leaves generous headroom for future components without inviting an
// unbounded decode.
const maxStatusBodyBytes = 16 << 10

// Handler serves POST /api/status. It implements http.Handler so cmd/main can mount it inside the host-token-protected mux, reusing the
// middleware that authenticates every other agent route.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New builds a status check-in handler. Panics if svc is nil (a wiring bug).
func New(svc api.Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("status.New: api.Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID, ok := api.HostIDFromContext(ctx)
	if !ok {
		// The host-token middleware pins host_id before this handler runs, so a miss means the route was mounted outside that middleware
		// (a wiring bug), not anything a client can provoke. Fail closed with the same 401 the middleware itself emits.
		httpserver.WriteAuthFailure(ctx, w, h.logger, http.StatusUnauthorized, "invalid_token")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxStatusBodyBytes)
	var report api.StatusReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if err := h.svc.RecordStatus(ctx, hostID, report); err != nil {
		if errors.Is(err, api.ErrInvalidStatusReport) {
			httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusBadRequest, map[string]string{"error": "invalid_status"})
			return
		}
		h.logger.ErrorContext(ctx, "record host status", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	trace.SpanFromContext(ctx).SetAttributes(attribute.String(attrkeys.HostID, hostID))
	w.WriteHeader(http.StatusNoContent)
}
