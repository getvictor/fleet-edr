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
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// createBodyCap caps POST /api/commands. Payload is operator-supplied JSON; 64 KiB is generous enough for a kill_process or any
// reasonable IR command without inviting a DoS vector via a session-authed endpoint.
const createBodyCap = 64 << 10

// Handler serves the operator-facing command routes.
type Handler struct {
	svc    api.Service
	authz  identityapi.AuthZ
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc or authz is nil. authz is the authorization chokepoint POST /api/commands and GET
// /api/commands/{id} gate on; a nil one would silently bypass the role matrix.
func New(svc api.Service, authz identityapi.AuthZ, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("response operator.New: api.Service must not be nil")
	}
	if authz == nil {
		panic("response operator.New: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, authz: authz, logger: logger}
}

// SetAudit installs the operator audit recorder. Optional: when not
// set, command issuance still works but no audit row is written.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes wires the two operator routes on the given mux.
// Caller wraps in identity.Session + identity.CSRF before mounting.
func (h *Handler) RegisterRoutes(mux httpserver.Router) {
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

	action, ok := commandTypeToAction(body.CommandType)
	if !ok {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "unsupported_command_type")
		return
	}
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, action, identityapi.Resource{Type: "host", ID: body.HostID}) {
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

	h.recordCommandAudit(r, body.HostID, body.CommandType, id)
	writeJSON(ctx, h.logger, w, http.StatusCreated, map[string]int64{"id": id})
}

// recordCommandAudit emits one audit row for the just-committed command issuance. target = the host receiving the command; payload
// carries command_type + command_id so a reviewer can reconstruct the exact action without joining commands. Soft-fail on audit error:
// the command row is authoritative.
func (h *Handler) recordCommandAudit(r *http.Request, hostID, commandType string, commandID int64) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	uid, _ := identityapi.UserIDFromContext(ctx)
	var userID *int64
	if uid > 0 {
		u := uid
		userID = &u
	}
	if err := h.audit.Record(ctx, identityapi.AuditEvent{
		UserID:     userID,
		Action:     identityapi.AuditCommandIssue,
		TargetType: "host",
		TargetID:   hostID,
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"command_type": commandType,
			"command_id":   commandID,
		},
	}); err != nil {
		h.logger.WarnContext(ctx, "audit record",
			"err", err, "action", string(identityapi.AuditCommandIssue),
			attrkeys.HostID, hostID,
		)
	}
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_command_id")
		return
	}
	// Fetch first so the chokepoint can gate on the command's host_id. Reading by id alone leaks "command N exists" but no payload,
	// and matches what GET /api/commands/{id} did before this PR. The chokepoint then enforces host.read against the resolved host so
	// future host-scoped roles can deny without special-casing the commands → host relationship at the policy layer.
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
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead,
		identityapi.Resource{Type: "host", ID: cmd.HostID}) {
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

// commandTypeToAction maps the wire-format command_type onto the
// authorization action the chokepoint evaluates. Returns ok=false on
// an unknown command_type so the handler can 400 before reaching the
// chokepoint; an unrecognised command_type is a request-validation
// failure, not a permission decision.
//
// kill_process is the wave-1 implemented type; isolate / run_script
// are reserved per the spec for wave-1 destructive actions and are
// validated here so the role matrix already covers them when the
// command-execution side ships.
func commandTypeToAction(commandType string) (identityapi.Action, bool) {
	switch commandType {
	case api.CommandTypeKillProcess:
		return identityapi.ActionHostKillProcess, true
	case "isolate":
		return identityapi.ActionHostIsolate, true
	case "run_script":
		return identityapi.ActionHostRunScript, true
	}
	return "", false
}
