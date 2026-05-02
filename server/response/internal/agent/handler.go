// Agent-facing routes (host-token gated by cmd/main):
//
//	GET /api/commands             - poll pending queue (heartbeat side effect)
//	PUT /api/commands/{id}        - ack / complete / fail a command

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/response/api"
)

// updateBodyCap caps the JSON body for PUT /api/commands/{id}. The
// agent only sends a tiny status + result blob (a few hundred bytes
// at most). 64 KiB matches phase 2's enroll cap as a defensive
// upper bound.
const updateBodyCap = 64 << 10

// Handler serves the agent-facing command routes.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New builds an agent handler. Panics if svc is nil.
func New(svc api.Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("response agent.New: api.Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

// RegisterRoutes wires the two agent routes on the given mux.
// Caller wraps in endpoint.HostToken middleware before mounting.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/commands", h.handleList)
	mux.HandleFunc("PUT /api/commands/{id}", h.handleUpdate)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID, ok := endpointapi.HostIDFromContext(ctx)
	if !ok {
		writeErr(ctx, h.logger, w, http.StatusUnauthorized, "host_context_missing")
		return
	}

	// The pinned host_id is authoritative -- any ?host_id= query
	// param is informational only so a valid token for host A
	// cannot read host B's commands. Status filter defaults to
	// pending so a no-filter call doesn't leak terminal rows
	// (completed / failed) back to the agent: the agent's commander
	// only knows how to dispatch new work, and re-delivering an
	// already-handled command would either double-execute or
	// produce a confused log line.
	status := api.StatusPending
	if q := r.URL.Query().Get("status"); q != "" {
		status = api.Status(q)
	}

	commands, err := h.svc.ListForHost(ctx, hostID, status)
	if err != nil {
		h.logger.ErrorContext(ctx, "list commands", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, commands)
}

type updateRequest struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_command_id")
		return
	}
	hostID, ok := endpointapi.HostIDFromContext(ctx)
	if !ok {
		writeErr(ctx, h.logger, w, http.StatusUnauthorized, "host_context_missing")
		return
	}

	var body updateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, updateBodyCap)).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}

	err = h.svc.UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: hostID,
		ID:     id,
		Status: api.Status(body.Status),
		Result: body.Result,
	})
	switch {
	case errors.Is(err, api.ErrCommandNotFound):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, api.ErrInvalidStatusTransition):
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_status")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "update command status", "id", id, "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
