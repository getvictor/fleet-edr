package operator

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

const (
	// Error codes for the `{"error": "<code>"}` JSON envelope this handler writes on 4xx / 5xx responses. The codes are
	// stable typed strings (server-rest-api JSON-response-format spec): clients dispatch on them without parsing the
	// human-readable message that may accompany them in logs but is NOT part of the response body.
	errInternal           = "internal"
	errNotFound           = "not_found"
	errInvalidJSONBody    = "invalid_json"
	errHostIDRequired     = "host_id_required"
	errInvalidPID         = "invalid_pid"
	errInvalidAlertID     = "invalid_alert_id"
	errInvalidStatus      = "invalid_status"
	errInvalidStatusTrans = "invalid_status_transition"
	errInvalidUser        = "invalid_user"

	// processTreeDefaultLimit is the row cap when the caller does not supply ?limit=. Sized to fit a typical analyst's investigation
	// without paging.
	processTreeDefaultLimit = 2000
	// processTreeMaxLimit is the upper bound the handler enforces; values above this are clamped down. Prevents an operator from
	// accidentally asking for the whole host's history in one query.
	processTreeMaxLimit = 5000

	// updateAlertStatusBodyCap bounds the PUT /api/alerts/{id} body so a malicious or buggy client can't exhaust server memory by
	// streaming a multi-GiB body that json.NewDecoder would happily buffer. The legitimate payload is ~20 bytes ({"status":"open"}
	// and the longest typed value); 1 MiB is generous headroom for forward-compatible field additions and gives a clean 413 path
	// that scripted clients can dispatch on. Mirrors the same cap shape that response/operator/handler.go uses on /api/commands.
	updateAlertStatusBodyCap = 1 << 20 // 1 MiB
)

// writeError emits a `{"error": "<code>"}` JSON body per the server-rest-api JSON-response-format requirement. Mirrors the pattern
// in server/response/internal/operator/handler.go and server/identity/internal/audit/handler.go so all session-authenticated
// endpoints surface failures with the same envelope a scripted client can dispatch on without parsing prose.
func (h *Handler) writeError(ctx context.Context, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, h.logger, w, status, map[string]string{"error": code})
}

// alertDetailResponse extends Alert with linked event IDs for the
// detail endpoint.
type alertDetailResponse struct {
	api.Alert
	EventIDs []string `json:"event_ids"`
}

// Handler serves the operator-facing detection routes.
type Handler struct {
	svc    api.Service
	authz  identityapi.AuthZ
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// New creates a detection operator handler. authz is the authorization chokepoint every privileged route gates on; callers also
// wrap the routes in the operator-session middleware (identity.Session, then identity.CSRF on unsafe methods) at registration time.
// Panics on nil svc or authz: a Handler without one would silently bypass the role matrix or nil-deref on the first request, neither
// of which is an acceptable boot-time silent failure.
func New(svc api.Service, authz identityapi.AuthZ, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("detection operator.New: api.Service must not be nil")
	}
	if authz == nil {
		panic("detection operator.New: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, authz: authz, logger: logger}
}

// SetAudit installs the operator audit recorder. Optional: when not set, alert-status changes still apply but no audit row is written.
// Bootstrap calls this after New so existing tests that pass nil for audit do not need to change.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes registers the operator routes on the given mux.
func (h *Handler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/hosts", h.handleListHosts)
	mux.HandleFunc("GET /api/hosts/{host_id}/tree", h.handleProcessTree)
	mux.HandleFunc("GET /api/hosts/{host_id}/processes/{pid}", h.handleProcessDetail)

	mux.HandleFunc("GET /api/alerts", h.handleListAlerts)
	mux.HandleFunc("GET /api/alerts/{id}", h.handleGetAlert)
	mux.HandleFunc("PUT /api/alerts/{id}", h.handleUpdateAlertStatus)
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host"}) {
		return
	}
	hosts, err := h.svc.ListHosts(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list hosts", "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	if hosts == nil {
		hosts = []api.HostSummary{}
	}
	h.writeJSON(w, r, hosts)
}

func (h *Handler) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		h.writeError(ctx, w, http.StatusBadRequest, errHostIDRequired)
		return
	}

	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process", ID: hostID}) {
		return
	}

	tr := httpserver.ParseTimeRange(r)
	limit := httpserver.ParseIntParam(r, "limit", processTreeDefaultLimit)
	if limit <= 0 {
		limit = processTreeDefaultLimit
	}
	if limit > processTreeMaxLimit {
		limit = processTreeMaxLimit
	}

	roots, err := h.svc.BuildTree(ctx, hostID, tr, limit)
	if err != nil {
		h.logger.ErrorContext(ctx, "build tree", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	if roots == nil {
		roots = []api.ProcessNode{}
	}
	h.writeJSON(w, r, map[string]any{"roots": roots})
}

func (h *Handler) handleProcessDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	pidStr := r.PathValue("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidPID)
		return
	}

	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process", ID: hostID}) {
		return
	}

	atTime := httpserver.ParseInt64Param(r, "at", time.Now().UnixNano())

	detail, err := h.svc.GetProcessDetail(ctx, hostID, pid, atTime)
	if err != nil {
		h.logger.ErrorContext(ctx, "get process detail", "host_id", hostID, "pid", pid, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	if detail == nil {
		h.writeError(ctx, w, http.StatusNotFound, errNotFound)
		return
	}
	h.writeJSON(w, r, detail)
}

func (h *Handler) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{Type: "alert"}) {
		return
	}
	f := api.AlertFilter{
		HostID:    r.URL.Query().Get("host_id"),
		Status:    api.AlertStatus(r.URL.Query().Get("status")),
		Severity:  r.URL.Query().Get("severity"),
		Source:    r.URL.Query().Get("source"),
		ProcessID: httpserver.ParseInt64Param(r, "process_id", 0),
		Limit:     httpserver.ParseIntParam(r, "limit", 100),
	}

	alerts, err := h.svc.ListAlerts(ctx, f)
	if err != nil {
		h.logger.ErrorContext(ctx, "list alerts", "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	if alerts == nil {
		alerts = []api.Alert{}
	}
	h.writeJSON(w, r, alerts)
}

func (h *Handler) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidAlertID)
		return
	}

	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{Type: "alert", ID: strconv.FormatInt(id, 10)}) {
		return
	}
	alert, eventIDs, err := h.svc.GetAlert(ctx, id)
	if err != nil {
		if errors.Is(err, api.ErrAlertNotFound) {
			h.writeError(ctx, w, http.StatusNotFound, errNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "get alert", "id", id, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	if eventIDs == nil {
		eventIDs = []string{}
	}
	h.writeJSON(w, r, alertDetailResponse{Alert: alert, EventIDs: eventIDs})
}

func (h *Handler) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidAlertID)
		return
	}

	// MaxBytesReader caps the body so a malicious client cannot stream an unbounded JSON document to OOM the server. Decode then maps
	// "request body too large" into the invalid_json envelope: the JSON shape doesn't distinguish the two failure modes, and the
	// downstream client retry is the same regardless (fix the body, resend). See updateAlertStatusBodyCap for the cap rationale.
	r.Body = http.MaxBytesReader(w, r.Body, updateAlertStatusBodyCap)
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidJSONBody)
		return
	}

	var action identityapi.Action
	switch body.Status {
	case string(api.AlertStatusOpen):
		action = identityapi.ActionAlertReopen
	case string(api.AlertStatusAcknowledged):
		action = identityapi.ActionAlertAcknowledge
	case string(api.AlertStatusResolved):
		action = identityapi.ActionAlertResolve
	default:
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidStatus)
		return
	}

	// alert.resolve on a critical-severity alert requires a fresh auth event. Fetch severity before the gate so the chokepoint
	// sees Resource.Severity. Other actions (Reopen, Acknowledge) don't need the read but the handler runs it uniformly. Alerts are small
	// + indexed and the row is hot in the buffer pool from the page-warm GET that typically precedes a status update. Fetching also lets
	// the 404 short-circuit before the chokepoint records an audit row for a non-existent alert.
	preGate, _, err := h.svc.GetAlert(ctx, id)
	if err != nil {
		if errors.Is(err, api.ErrAlertNotFound) {
			h.writeError(ctx, w, http.StatusNotFound, errNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "pre-gate alert lookup", "id", id, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}

	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, action, identityapi.Resource{
		Type:     "alert",
		ID:       strconv.FormatInt(id, 10),
		Severity: preGate.Severity,
	}) {
		return
	}
	userID, _ := identityapi.UserIDFromContext(ctx)
	if _, err := h.svc.UpdateAlertStatus(ctx, id, api.AlertStatus(body.Status), userID); err != nil {
		switch {
		case errors.Is(err, api.ErrAlertNotFound):
			h.writeError(ctx, w, http.StatusNotFound, errNotFound)
			return
		case errors.Is(err, api.ErrInvalidAlertTransition):
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidStatusTrans)
			return
		case errors.Is(err, api.ErrInvalidUserUpdater):
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidUser)
			return
		}
		h.logger.ErrorContext(ctx, "update alert status", "id", id, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}

	if userID > 0 {
		h.logger.InfoContext(ctx, "alert status updated",
			attrkeys.AdminAction, "alert_update",
			"edr.alert.id", id,
			"edr.alert.status", body.Status,
			attrkeys.UserID, userID,
		)
	}

	h.recordAlertStatusAudit(r, id, body.Status, userID)
	w.WriteHeader(http.StatusNoContent)
}

// recordAlertStatusAudit emits one audit row for the just-committed alert-status change. Action is per-status so SIEM filters can
// scope to "all acks" vs "all resolves" without parsing payload. Audit failures are soft: the action committed; a missing audit row is
// a follow-up incident, not a reason to fail an HTTP response that already returned 204.
func (h *Handler) recordAlertStatusAudit(r *http.Request, alertID int64, newStatus string, userID int64) {
	if h.audit == nil {
		return
	}
	var action identityapi.AuditAction
	switch newStatus {
	case string(api.AlertStatusAcknowledged):
		action = identityapi.AuditAlertAcknowledge
	case string(api.AlertStatusResolved):
		action = identityapi.AuditAlertResolve
	case string(api.AlertStatusOpen):
		action = identityapi.AuditAlertReopen
	default:
		return // status validated above; an unknown one would be a programming error.
	}
	var uid *int64
	if userID > 0 {
		u := userID
		uid = &u
	}
	if err := h.audit.Record(r.Context(), identityapi.AuditEvent{
		UserID:     uid,
		Action:     action,
		TargetType: "alert",
		TargetID:   strconv.FormatInt(alertID, 10),
		RemoteAddr: httpserver.ClientIP(r),
		Payload:    map[string]any{"new_status": newStatus},
	}); err != nil {
		h.logger.WarnContext(r.Context(), "audit record",
			"err", err,
			"action", string(action),
			"edr.alert.id", alertID,
		)
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.ErrorContext(r.Context(), "writeJSON encode failed", "err", err)
	}
}
