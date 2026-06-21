// Package saadmin serves the service-account admin surface (issue #376, ADR-0013): the operator CRUD API behind the authz chokepoint,
// and the client-credentials token endpoint (token.go). Lifecycle mutations and token issuance are audited; secrets are returned once
// and never logged.
package saadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
)

const (
	day = 24 * time.Hour
	// defaultLifetime is the credential lifetime when the caller does not specify one; maxLifetime caps any caller-supplied value.
	defaultLifetime = 90 * day
	maxLifetime     = 365 * day
	// maxLifetimeDays mirrors maxLifetime as an integer-day count so the caller's day value can be clamped BEFORE the int->Duration
	// multiply, avoiding an overflow that would wrap a huge day count to a small positive duration.
	maxLifetimeDays = 365
	// maxNameLen matches the service_accounts.name column width.
	maxNameLen = 255

	// maxBodyBytes bounds the create request body.
	maxBodyBytes = 16 << 10
)

// bindableRoles is the set of seeded roles a service account may be bound to. admin is permitted at operator discretion (an
// admin-bound service account holds the console-management actions, including service_account.*, so its token is a full-control
// credential that can mint more service accounts: grant it only when automation genuinely needs admin). super_admin remains excluded:
// a non-human credential with the unrestricted wildcard is never warranted. When custom roles land, this becomes a grant-based check.
var bindableRoles = map[string]bool{
	"analyst":        true,
	"senior_analyst": true,
	"auditor":        true,
	"admin":          true,
}

// ManagementStore is the persistence the CRUD handler needs.
type ManagementStore interface {
	List(ctx context.Context) ([]serviceaccounts.ServiceAccount, error)
	Create(ctx context.Context, in serviceaccounts.CreateInput) (serviceaccounts.ServiceAccount, string, error)
	Rotate(ctx context.Context, id int64) (string, error)
	Revoke(ctx context.Context, id int64) error
}

// AuditRecorder records lifecycle audit rows.
type AuditRecorder interface {
	Record(ctx context.Context, e api.AuditEvent) error
}

// Handler serves the service-account management API.
type Handler struct {
	store  ManagementStore
	authz  api.AuthZ
	audit  AuditRecorder
	logger *slog.Logger
	now    func() time.Time
}

// NewHandler constructs the management handler. now defaults to time.Now when nil.
func NewHandler(store ManagementStore, authz api.AuthZ, audit AuditRecorder, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: store, authz: authz, audit: audit, logger: logger, now: time.Now}
}

// RegisterAuthedRoutes mounts the CRUD routes. The caller wraps the mux in the session/bearer auth + CSRF chain.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/settings/service-accounts", h.handleList)
	mux.HandleFunc("POST /api/settings/service-accounts", h.handleCreate)
	mux.HandleFunc("POST /api/settings/service-accounts/{id}/rotate", h.handleRotate)
	mux.HandleFunc("DELETE /api/settings/service-accounts/{id}", h.handleRevoke)
}

type saView struct {
	ID         int64      `json:"id"`
	ClientID   string     `json:"client_id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (h *Handler) view(sa serviceaccounts.ServiceAccount) saView {
	v := saView{
		ID: sa.ID, ClientID: sa.ClientID, Name: sa.Name, Role: sa.RoleID,
		CreatedAt: sa.CreatedAt.UTC(), ExpiresAt: sa.ExpiresAt.UTC(),
		Status: h.status(sa),
	}
	if sa.LastUsedAt.Valid {
		t := sa.LastUsedAt.Time.UTC()
		v.LastUsedAt = &t
	}
	return v
}

func (h *Handler) status(sa serviceaccounts.ServiceAccount) string {
	switch {
	case sa.RevokedAt.Valid:
		return "revoked"
	case !sa.ExpiresAt.After(h.now()):
		return "expired"
	default:
		return "active"
	}
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionServiceAccountRead, api.Resource{Type: "service_account"}) {
		return
	}
	rows, err := h.store.List(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account list", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	out := make([]saView, len(rows))
	for i, sa := range rows {
		out[i] = h.view(sa)
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"service_accounts": out})
}

type createRequest struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	ExpiresInDays *int   `json:"expires_in_days,omitempty"`
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionServiceAccountCreate, api.Resource{Type: "service_account"}) {
		return
	}
	var req createRequest
	if !decodeBody(ctx, h.logger, w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "missing_name")
		return
	}
	if len(name) > maxNameLen {
		// The column is VARCHAR(255); reject overlong names with a 400 rather than letting the insert fail as a 500.
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "name_too_long")
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if !bindableRoles[role] {
		// Covers admin/super_admin (management-capable) and unknown roles alike.
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_role")
		return
	}
	expiresAt := h.resolveExpiry(req.ExpiresInDays)

	var createdBy *int64
	if actor, ok := api.ActorFromContext(ctx); ok && actor.UserID > 0 {
		uid := actor.UserID
		createdBy = &uid
	}
	sa, secret, err := h.store.Create(ctx, serviceaccounts.CreateInput{
		Name: name, RoleID: role, CreatedBy: createdBy, ExpiresAt: expiresAt,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account create", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	h.recordLifecycle(ctx, r, "service_account.created", sa.ClientID, map[string]any{"name": sa.Name, "role": sa.RoleID})

	resp := struct {
		saView
		Secret string `json:"secret"`
	}{saView: h.view(sa), Secret: secret}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusCreated, resp)
}

func (h *Handler) handleRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionServiceAccountRotate, api.Resource{Type: "service_account"}) {
		return
	}
	id, ok := pathID(ctx, h.logger, w, r)
	if !ok {
		return
	}
	secret, err := h.store.Rotate(ctx, id)
	if errors.Is(err, serviceaccounts.ErrNotFound) {
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account rotate", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	h.recordLifecycle(ctx, r, "service_account.rotated", strconv.FormatInt(id, 10), nil)
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, map[string]string{"secret": secret})
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionServiceAccountRevoke, api.Resource{Type: "service_account"}) {
		return
	}
	id, ok := pathID(ctx, h.logger, w, r)
	if !ok {
		return
	}
	err := h.store.Revoke(ctx, id)
	if errors.Is(err, serviceaccounts.ErrNotFound) {
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account revoke", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	h.recordLifecycle(ctx, r, "service_account.revoked", strconv.FormatInt(id, 10), nil)
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, map[string]string{"status": "revoked"})
}

// resolveExpiry returns the absolute expiry: caller days when given (clamped to (0, maxLifetime]), else the default lifetime.
func (h *Handler) resolveExpiry(days *int) time.Time {
	lifetime := defaultLifetime
	if days != nil {
		// Clamp the integer day count before converting to a Duration: a huge *days (>~213506) would overflow time.Duration and wrap
		// to a small positive value, silently yielding a near-immediate expiry.
		switch {
		case *days <= 0:
			lifetime = defaultLifetime
		case *days >= maxLifetimeDays:
			lifetime = maxLifetime
		default:
			lifetime = time.Duration(*days) * day
		}
	}
	return h.now().Add(lifetime).UTC()
}

func (h *Handler) recordLifecycle(ctx context.Context, r *http.Request, action, targetID string, payload map[string]any) {
	if h.audit == nil {
		return
	}
	var uid *int64
	if actor, ok := api.ActorFromContext(ctx); ok && actor.UserID > 0 {
		id := actor.UserID
		uid = &id
	}
	if err := h.audit.Record(ctx, api.AuditEvent{
		UserID:     uid,
		Action:     api.AuditAction(action),
		TargetType: "service_account",
		TargetID:   targetID,
		RemoteAddr: httpserver.ClientIP(r),
		Payload:    payload,
	}); err != nil {
		h.logger.ErrorContext(ctx, "service-account audit record failed", "err", err)
	}
}

func pathID(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(ctx, logger, w, http.StatusBadRequest, "invalid_id")
		return 0, false
	}
	return id, true
}

func decodeBody(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeErr(ctx, logger, w, http.StatusBadRequest, "read_error")
		return false
	}
	if len(body) > maxBodyBytes {
		writeErr(ctx, logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeErr(ctx, logger, w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, reason string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": reason})
}
