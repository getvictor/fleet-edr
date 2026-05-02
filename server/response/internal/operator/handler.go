// Operator-facing routes (session-gated + CSRF-gated by cmd/main):
//
//	POST /api/commands           - admin issues a command for a target host
//	GET  /api/commands/{id}      - admin reads a single command by id

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/response/api"
)

// createBodyCap caps POST /api/commands. Payload is operator-supplied
// JSON; 64 KiB is generous enough for a kill_process or any
// reasonable IR command without inviting a DoS vector via a
// session-authed endpoint.
const createBodyCap = 64 << 10

// Handler serves the operator-facing command routes.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc is nil.
func New(svc api.Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("response operator.New: api.Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

// RegisterRoutes wires the two operator routes on the given mux.
// Caller wraps in identity.Session + identity.CSRF before mounting.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/commands", h.handleCreate)
	mux.HandleFunc("GET /api/commands/{id}", h.handleGet)
}

type createRequest struct {
	HostID      string          `json:"host_id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, createBodyCap)).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}

	id, err := h.svc.Insert(ctx, body.HostID, body.CommandType, body.Payload)
	switch {
	case errors.Is(err, api.ErrInvalidInsertRequest):
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_request")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "create command", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "command_create"),
		attribute.String(attrkeys.HostID, body.HostID),
		attribute.String("edr.command.type", body.CommandType),
		attribute.Int64("edr.command.id", id),
	)
	h.logger.InfoContext(ctx, "admin command issued",
		attrkeys.AdminAction, "command_create",
		attrkeys.HostID, body.HostID,
		"edr.command.type", body.CommandType,
		"edr.command.id", id,
	)

	writeJSON(ctx, h.logger, w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_command_id")
		return
	}
	cmd, err := h.svc.Get(ctx, id)
	switch {
	case errors.Is(err, api.ErrCommandNotFound):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "get command", "id", id, "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, cmd)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
