// Package tracingadmin serves the super-admin API for the deployment's runtime OTel trace-sampling settings (issue #374): read the
// current per-tier ratios + force-full toggle, and update them without a redeploy. Both routes funnel through the authorization
// chokepoint on api.ActionTracingManage (admin + super_admin); the update emits an audit row. The handler depends on a small store
// interface so it is unit-testable without a database.
package tracingadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/observability/internal/tracingconfig"
)

// updateBodyLimit caps the PATCH body. The payload is three short fields; 64 KiB is generous.
const updateBodyLimit = 1 << 16

// store is the subset of *tracingconfig.Store the handler needs. Narrowed to an interface so tests inject a fake. Get returns the row
// version so Update can apply optimistic concurrency; Update returns tracingconfig.ErrVersionConflict when a concurrent write landed.
type store interface {
	Get(ctx context.Context) (*tracing.Settings, int64, error)
	Update(ctx context.Context, settings tracing.Settings, expectedVersion int64, updatedBy string) error
}

// Handler serves the /api/settings/tracing routes. Construct via NewHandler; mount with RegisterAuthedRoutes behind the session + CSRF
// middleware (PATCH inherits the CSRF check from that wrapper).
type Handler struct {
	store  store
	authz  api.AuthZ
	audit  api.AuditRecorder
	logger *slog.Logger
}

// NewHandler builds the handler. store and authz are load-bearing; logger defaults to slog.Default. audit may be nil only in tests
// that do not assert on the audit row.
func NewHandler(store store, authz api.AuthZ, audit api.AuditRecorder, logger *slog.Logger) *Handler {
	if store == nil {
		panic("tracingadmin.NewHandler: store is required")
	}
	if authz == nil {
		panic("tracingadmin.NewHandler: authz is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: store, authz: authz, audit: audit, logger: logger}
}

// RegisterAuthedRoutes mounts the tracing settings routes. The mux is expected to be wrapped in the session + CSRF middleware before
// being mounted; the PATCH inherits the CSRF check from that wrapper.
func (h *Handler) RegisterAuthedRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/settings/tracing", h.handleGet)
	mux.HandleFunc("PATCH /api/settings/tracing", h.handleUpdate)
}

// settingsResponse is the read shape. updated_at is intentionally omitted; the UI shows the live knobs, not write provenance.
type settingsResponse struct {
	HighVolumeRatio float64 `json:"high_volume_ratio"`
	StandardRatio   float64 `json:"standard_ratio"`
	ForceFull       bool    `json:"force_full"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionTracingManage, api.Resource{Type: "tracing_config"}) {
		return
	}
	got, _, err := h.store.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "tracing settings get", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(got))
}

// updateRequest uses pointers so an omitted field keeps the stored value (PATCH semantics): an operator can flip force_full alone
// without restating the ratios.
type updateRequest struct {
	HighVolumeRatio *float64 `json:"high_volume_ratio"`
	StandardRatio   *float64 `json:"standard_ratio"`
	ForceFull       *bool    `json:"force_full"`
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionTracingManage, api.Resource{Type: "tracing_config"}) {
		return
	}
	var req updateRequest
	r.Body = http.MaxBytesReader(w, r.Body, updateBodyLimit)
	// DisallowUnknownFields rejects misspelled keys (e.g. {"forcefull":true}) instead of silently no-op'ing a 200; the trailing
	// Decode(&struct{}) != io.EOF check rejects extra JSON after the object so a garbage suffix can't ride along on a valid body.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_json")
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_json")
		return
	}
	// Read-modify-write so an absent field keeps its stored value; the row version drives the optimistic-concurrency check on Update.
	cur, version, err := h.store.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "tracing settings read for update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	next := *cur
	if req.HighVolumeRatio != nil {
		next.HighVolumeRatio = *req.HighVolumeRatio
	}
	if req.StandardRatio != nil {
		next.StandardRatio = *req.StandardRatio
	}
	if req.ForceFull != nil {
		next.ForceFull = *req.ForceFull
	}
	if !validRatio(next.HighVolumeRatio) || !validRatio(next.StandardRatio) {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "ratio_out_of_range")
		return
	}
	actor, ok := api.ActorFromContext(ctx)
	if !ok {
		// Session middleware guarantees an actor past HTTPGate's allow path; its absence here is a wiring bug.
		h.logger.ErrorContext(ctx, "tracing settings update: no actor on context")
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	if err := h.store.Update(ctx, next, version, actor.Principal.ID); err != nil {
		if errors.Is(err, tracingconfig.ErrVersionConflict) {
			writeErr(ctx, h.logger, w, http.StatusConflict, "version_conflict")
			return
		}
		h.logger.ErrorContext(ctx, "tracing settings update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	h.recordUpdate(ctx, r, actor.Principal, next)

	got, _, err := h.store.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "tracing settings re-read after update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(got))
}

func validRatio(v float64) bool { return v >= 0 && v <= 1 }

func toResponse(s *tracing.Settings) settingsResponse {
	return settingsResponse{
		HighVolumeRatio: s.HighVolumeRatio,
		StandardRatio:   s.StandardRatio,
		ForceFull:       s.ForceFull,
	}
}

// recordUpdate emits the mutation audit row.
func (h *Handler) recordUpdate(ctx context.Context, r *http.Request, actor api.PrincipalRef, s tracing.Settings) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(ctx, api.AuditEvent{
		Actor:      actor,
		Action:     api.AuditAction("tracing.settings.updated"),
		TargetType: "tracing_config",
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"high_volume_ratio": s.HighVolumeRatio,
			"standard_ratio":    s.StandardRatio,
			"force_full":        s.ForceFull,
		},
	}); err != nil {
		h.logger.ErrorContext(ctx, "tracing settings audit record failed", "err", err)
	}
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
