// Package useradmin serves the admin user-management surface (issue #135): list operators, set a user's role, and enable/disable a
// user, all behind the authz chokepoint and audited. Role changes use the wave-2 single-global-binding model (see SetUserRole). The
// guardrails (last-admin, no self-management, break-glass immutable, super_admin restricted) live here because they concern the target,
// not the actor's role; the chokepoint answers only "may this actor manage users."
package useradmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

const (
	statusActive   = "active"
	statusDisabled = "disabled"
	roleSuperAdmin = "super_admin"
	roleAdmin      = "admin"
	// maxBodyBytes bounds a mutation request body; the bodies are tiny ({"role":"..."} / {"status":"..."}).
	maxBodyBytes = 4 << 10
)

// bindableRoles is the set of seeded roles the UI offers and an admin may grant. super_admin is excluded here and handled separately:
// only a super_admin actor may grant it (the UI never offers it). When custom roles land this becomes a grant-based check.
var bindableRoles = map[string]bool{
	"analyst":        true,
	"senior_analyst": true,
	"auditor":        true,
	roleAdmin:        true,
}

// roleRank orders the seeded roles so the list can show a single effective role when a user (via legacy hand-written SQL) holds more
// than one global binding. Higher wins.
//
//nolint:mnd // ordinal ranks of the seeded roles, not magic constants
var roleRank = map[string]int{roleSuperAdmin: 5, roleAdmin: 4, "senior_analyst": 3, "analyst": 2, "auditor": 1}

// UsersStore is the users-table surface the handler needs.
type UsersStore interface {
	List(ctx context.Context) ([]users.AdminUser, error)
	GetAdmin(ctx context.Context, id int64) (*users.AdminUser, error)
	SetStatus(ctx context.Context, id int64, status string) error
}

// RolesStore is the role_bindings surface the handler needs.
type RolesStore interface {
	AllLiveBindings(ctx context.Context) (map[int64][]string, error)
	LiveGlobalRoles(ctx context.Context, userID int64) ([]string, error)
	SetUserRole(ctx context.Context, userID int64, roleID string) (previous []string, err error)
	CountActiveAdmins(ctx context.Context, excludeUserID int64) (int, error)
}

// AuditRecorder records lifecycle audit rows.
type AuditRecorder interface {
	Record(ctx context.Context, e api.AuditEvent) error
}

// Handler serves the user-management API.
type Handler struct {
	users  UsersStore
	roles  RolesStore
	authz  api.AuthZ
	audit  AuditRecorder
	logger *slog.Logger
}

// NewHandler constructs the user-management handler.
func NewHandler(usersStore UsersStore, rolesStore RolesStore, authz api.AuthZ, audit AuditRecorder, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{users: usersStore, roles: rolesStore, authz: authz, audit: audit, logger: logger}
}

// RegisterAuthedRoutes mounts the routes. The caller wraps the mux in the session auth + CSRF chain.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/settings/users", h.handleList)
	mux.HandleFunc("PUT /api/settings/users/{id}/role", h.handleSetRole)
	mux.HandleFunc("PUT /api/settings/users/{id}/status", h.handleSetStatus)
}

type userView struct {
	ID           int64    `json:"id"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name,omitempty"`
	Role         string   `json:"role"`
	Roles        []string `json:"roles"`
	Status       string   `json:"status"`
	IsBreakglass bool     `json:"is_breakglass"`
}

func view(u users.AdminUser, roles []string) userView {
	if roles == nil {
		// A user with no live global binding has no map entry; serialize roles as [] (not null) so the wire contract stays an array.
		roles = []string{}
	}
	return userView{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName.String,
		Role: effectiveRole(roles), Roles: roles, Status: u.Status, IsBreakglass: u.IsBreakglass,
	}
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionUserRead, api.Resource{Type: "user"}) {
		return
	}
	rows, err := h.users.List(ctx)
	if err != nil {
		h.internal(ctx, w, "user list", err)
		return
	}
	bindings, err := h.roles.AllLiveBindings(ctx)
	if err != nil {
		h.internal(ctx, w, "user list bindings", err)
		return
	}
	out := make([]userView, len(rows))
	for i, u := range rows {
		out[i] = view(u, bindings[u.ID])
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"users": out})
}

type roleRequest struct {
	Role string `json:"role"`
}

func (h *Handler) handleSetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionUserManage, api.Resource{Type: "user"}) {
		return
	}
	id, ok := pathID(ctx, h.logger, w, r)
	if !ok {
		return
	}
	var req roleRequest
	if !decodeBody(ctx, h.logger, w, r, &req) {
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	actorSuper := h.actorIsSuperAdmin(ctx)
	if role == roleSuperAdmin {
		// Only a super_admin actor may grant super_admin; the UI never offers it.
		if !actorSuper {
			writeErr(ctx, h.logger, w, http.StatusForbidden, "super_admin_forbidden")
			return
		}
	} else if !bindableRoles[role] {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_role")
		return
	}

	target, current, ok := h.loadTarget(ctx, w, id)
	if !ok {
		return
	}
	if !h.guardTarget(ctx, w, target, current, actorSuper) {
		return
	}
	// No-op: the user already holds exactly this one role. Succeed without mutating or auditing so the trail records changes, not clicks.
	if len(current) == 1 && current[0] == role {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, view(*target, current))
		return
	}
	// Last-admin guard: demoting an admin-tier target away from admin-tier must leave at least one other active admin.
	if isAdminTier(current) && !isAdminTier([]string{role}) {
		if !h.hasOtherActiveAdmin(ctx, w, id) {
			return
		}
	}

	previous, err := h.roles.SetUserRole(ctx, id, role)
	if err != nil {
		h.internal(ctx, w, "set user role", err)
		return
	}
	action := api.AuditRoleBindingUpdate
	if len(previous) == 0 {
		action = api.AuditRoleBindingCreate
	}
	h.record(ctx, r, action, id, map[string]any{"from": previous, "to": role})
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, view(*target, []string{role}))
}

type statusRequest struct {
	Status string `json:"status"`
}

func (h *Handler) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionUserManage, api.Resource{Type: "user"}) {
		return
	}
	id, ok := pathID(ctx, h.logger, w, r)
	if !ok {
		return
	}
	var req statusRequest
	if !decodeBody(ctx, h.logger, w, r, &req) {
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != statusActive && status != statusDisabled {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_status")
		return
	}

	target, current, ok := h.loadTarget(ctx, w, id)
	if !ok {
		return
	}
	if !h.guardTarget(ctx, w, target, current, h.actorIsSuperAdmin(ctx)) {
		return
	}
	if target.Status == status {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, view(*target, current))
		return
	}
	// Last-admin guard: disabling an admin-tier target must leave at least one other active admin.
	if status == statusDisabled && isAdminTier(current) {
		if !h.hasOtherActiveAdmin(ctx, w, id) {
			return
		}
	}

	if err := h.users.SetStatus(ctx, id, status); err != nil {
		h.internal(ctx, w, "set user status", err)
		return
	}
	action := api.AuditUserEnabled
	if status == statusDisabled {
		action = api.AuditUserDisabled
	}
	h.record(ctx, r, action, id, nil)
	target.Status = status
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, view(*target, current))
}

// loadTarget reads the target user + its current global roles, writing the 404 / 500 response and returning ok=false on failure.
func (h *Handler) loadTarget(ctx context.Context, w http.ResponseWriter, id int64) (*users.AdminUser, []string, bool) {
	target, err := h.users.GetAdmin(ctx, id)
	if errors.Is(err, users.ErrNotFound) {
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return nil, nil, false
	}
	if err != nil {
		h.internal(ctx, w, "load target user", err)
		return nil, nil, false
	}
	current, err := h.roles.LiveGlobalRoles(ctx, id)
	if err != nil {
		h.internal(ctx, w, "load target roles", err)
		return nil, nil, false
	}
	return target, current, true
}

// guardTarget enforces the target-side invariants common to both mutations: break-glass is immutable, an operator cannot modify
// themselves, and an admin actor cannot touch a user who holds super_admin. Returns false (after writing the response) on a violation.
func (h *Handler) guardTarget(ctx context.Context, w http.ResponseWriter, target *users.AdminUser, current []string, actorSuper bool) bool {
	if target.IsBreakglass {
		writeErr(ctx, h.logger, w, http.StatusConflict, "breakglass_immutable")
		return false
	}
	if actor, ok := api.ActorFromContext(ctx); ok && actor.UserID == target.ID {
		writeErr(ctx, h.logger, w, http.StatusConflict, "cannot_modify_self")
		return false
	}
	if !actorSuper && slices.Contains(current, roleSuperAdmin) {
		writeErr(ctx, h.logger, w, http.StatusForbidden, "super_admin_forbidden")
		return false
	}
	return true
}

// hasOtherActiveAdmin returns true when at least one active admin-tier user other than excludeID exists. On false it writes the 409
// last_admin response; on a store error it writes the 500. Either way a false return means the caller must stop.
func (h *Handler) hasOtherActiveAdmin(ctx context.Context, w http.ResponseWriter, excludeID int64) bool {
	n, err := h.roles.CountActiveAdmins(ctx, excludeID)
	if err != nil {
		h.internal(ctx, w, "count active admins", err)
		return false
	}
	if n < 1 {
		writeErr(ctx, h.logger, w, http.StatusConflict, "last_admin")
		return false
	}
	return true
}

func (h *Handler) actorIsSuperAdmin(ctx context.Context) bool {
	actor, ok := api.ActorFromContext(ctx)
	if !ok {
		return false
	}
	for _, b := range actor.Roles {
		if b.RoleID == roleSuperAdmin {
			return true
		}
	}
	return false
}

func (h *Handler) record(ctx context.Context, r *http.Request, action api.AuditAction, targetID int64, payload map[string]any) {
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
		Action:     action,
		TargetType: "user",
		TargetID:   strconv.FormatInt(targetID, 10),
		RemoteAddr: httpserver.ClientIP(r),
		Payload:    payload,
	}); err != nil {
		h.logger.ErrorContext(ctx, "user-management audit record failed", "err", err)
	}
}

func (h *Handler) internal(ctx context.Context, w http.ResponseWriter, what string, err error) {
	h.logger.ErrorContext(ctx, what, "err", err)
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
}

func effectiveRole(roles []string) string {
	best, bestRank := "", -1
	for _, r := range roles {
		if roleRank[r] > bestRank {
			best, bestRank = r, roleRank[r]
		}
	}
	return best
}

func isAdminTier(roles []string) bool {
	return slices.Contains(roles, roleAdmin) || slices.Contains(roles, roleSuperAdmin)
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
