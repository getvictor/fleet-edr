package operator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// Additional error codes for the webhook admin surface.
const (
	errWebhookInvalid       = "invalid_webhook"
	errWebhookNotConfigured = "webhook_not_configured"
	errInvalidWebhookID     = "invalid_webhook_id"

	// webhookBodyCap bounds the create/update request body (a destination is a name + URL + secret + filters, well under this).
	webhookBodyCap = 1 << 20 // 1 MiB
	// webhookDeliveriesDefaultLimit caps the delivery-status readout when the caller does not supply ?limit=.
	webhookDeliveriesDefaultLimit = 50
)

// WebhookAdmin is the outbound-webhook configuration surface the operator handler serves. mysql.Store satisfies it. It is a dependency
// distinct from api.Service so the alert/host read interface (and its test mocks) stay untouched.
type WebhookAdmin interface {
	CreateWebhookDestination(ctx context.Context, in api.WebhookDestinationInput) (int64, error)
	ListWebhookDestinations(ctx context.Context) ([]api.WebhookDestination, error)
	GetWebhookDestination(ctx context.Context, id int64) (api.WebhookDestination, error)
	UpdateWebhookDestination(ctx context.Context, id int64, in api.WebhookDestinationInput) error
	DeleteWebhookDestination(ctx context.Context, id int64) error
	ListWebhookDeliveries(ctx context.Context, destinationID int64, limit int) ([]api.WebhookDelivery, error)
}

// SetWebhookAdmin installs the webhook configuration surface. Optional: when not set (a deployment with no root secret), the webhook
// routes respond 503 webhook_not_configured. Bootstrap calls this after New.
func (h *Handler) SetWebhookAdmin(a WebhookAdmin) { h.webhookAdmin = a }

func (h *Handler) registerWebhookRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/settings/webhooks", h.handleListWebhooks)
	mux.HandleFunc("POST /api/settings/webhooks", h.handleCreateWebhook)
	mux.HandleFunc("PUT /api/settings/webhooks/{id}", h.handleUpdateWebhook)
	mux.HandleFunc("DELETE /api/settings/webhooks/{id}", h.handleDeleteWebhook)
	mux.HandleFunc("GET /api/settings/webhooks/{id}/deliveries", h.handleListWebhookDeliveries)
}

// gateWebhook runs the shared authz + configured checks every webhook route funnels through. It returns false (and has written the
// response) when the caller should stop.
func (h *Handler) gateWebhook(w http.ResponseWriter, r *http.Request) bool {
	if !identityapi.HTTPGate(r.Context(), w, h.authz, h.logger, identityapi.ActionWebhookManage, identityapi.Resource{Type: "webhook"}) {
		return false
	}
	if h.webhookAdmin == nil {
		h.writeError(r.Context(), w, http.StatusServiceUnavailable, errWebhookNotConfigured)
		return false
	}
	return true
}

func (h *Handler) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	if !h.gateWebhook(w, r) {
		return
	}
	dests, err := h.webhookAdmin.ListWebhookDestinations(r.Context())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "list webhook destinations", "err", err)
		h.writeError(r.Context(), w, http.StatusInternalServerError, errInternal)
		return
	}
	if dests == nil {
		dests = []api.WebhookDestination{}
	}
	h.writeJSON(w, r, dests)
}

func (h *Handler) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.gateWebhook(w, r) {
		return
	}
	in, ok := h.decodeWebhookInput(w, r)
	if !ok {
		return
	}
	id, err := h.webhookAdmin.CreateWebhookDestination(r.Context(), in)
	if err != nil {
		h.writeWebhookErr(w, r, err)
		return
	}
	created, err := h.webhookAdmin.GetWebhookDestination(r.Context(), id)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "read created webhook destination", "err", err)
		h.writeError(r.Context(), w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, created)
}

func (h *Handler) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.gateWebhook(w, r) {
		return
	}
	id, ok := h.webhookID(w, r)
	if !ok {
		return
	}
	in, ok := h.decodeWebhookInput(w, r)
	if !ok {
		return
	}
	if err := h.webhookAdmin.UpdateWebhookDestination(r.Context(), id, in); err != nil {
		h.writeWebhookErr(w, r, err)
		return
	}
	updated, err := h.webhookAdmin.GetWebhookDestination(r.Context(), id)
	if err != nil {
		h.writeWebhookErr(w, r, err)
		return
	}
	h.writeJSON(w, r, updated)
}

func (h *Handler) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.gateWebhook(w, r) {
		return
	}
	id, ok := h.webhookID(w, r)
	if !ok {
		return
	}
	if err := h.webhookAdmin.DeleteWebhookDestination(r.Context(), id); err != nil {
		h.writeWebhookErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if !h.gateWebhook(w, r) {
		return
	}
	id, ok := h.webhookID(w, r)
	if !ok {
		return
	}
	limit := httpserver.ParseIntParam(r, "limit", webhookDeliveriesDefaultLimit)
	deliveries, err := h.webhookAdmin.ListWebhookDeliveries(r.Context(), id, limit)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "list webhook deliveries", "err", err)
		h.writeError(r.Context(), w, http.StatusInternalServerError, errInternal)
		return
	}
	if deliveries == nil {
		deliveries = []api.WebhookDelivery{}
	}
	h.writeJSON(w, r, deliveries)
}

func (h *Handler) webhookID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		h.writeError(r.Context(), w, http.StatusBadRequest, errInvalidWebhookID)
		return 0, false
	}
	return id, true
}

func (h *Handler) decodeWebhookInput(w http.ResponseWriter, r *http.Request) (api.WebhookDestinationInput, bool) {
	var in api.WebhookDestinationInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, webhookBodyCap))
	if err := dec.Decode(&in); err != nil {
		h.writeError(r.Context(), w, http.StatusBadRequest, errInvalidJSONBody)
		return api.WebhookDestinationInput{}, false
	}
	return in, true
}

// writeWebhookErr maps store errors to response codes: not-found to 404, an unconfigured sealer to 503 (a deployment issue the
// operator cannot fix), and every validation error (bad URL, missing name/secret, unknown event type, invalid severity) to 400.
func (h *Handler) writeWebhookErr(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	switch {
	case errors.Is(err, mysql.ErrWebhookNotFound):
		h.writeError(ctx, w, http.StatusNotFound, errNotFound)
	case errors.Is(err, mysql.ErrWebhookSealerUnset):
		h.writeError(ctx, w, http.StatusServiceUnavailable, errWebhookNotConfigured)
	case errors.Is(err, mysql.ErrWebhookName),
		errors.Is(err, mysql.ErrWebhookSecretMissing),
		errors.Is(err, mysql.ErrWebhookEventTypes),
		errors.Is(err, mysql.ErrWebhookSeverity),
		errors.Is(err, webhook.ErrBlockedURL):
		h.writeError(ctx, w, http.StatusBadRequest, errWebhookInvalid)
	default:
		h.logger.ErrorContext(ctx, "webhook admin", "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
	}
}
