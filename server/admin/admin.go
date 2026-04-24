// Package admin exposes the operator endpoints:
//
//   - Phase 1: list enrollments, revoke an individual host.
//   - Phase 2: get + update the server-driven blocklist policy.
//
// All endpoints are gated on the admin token by server-side middleware (not by this
// package). Every state-changing call emits an audit log + span attributes so SOC teams
// can reconstruct what changed and when.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

// CommandInserter is the narrow interface admin needs to queue set_blocklist commands. Kept
// as an interface so tests can substitute a recording double; in production it's satisfied
// by *store.Store.
type CommandInserter interface {
	InsertCommand(ctx context.Context, c store.Command) (int64, error)
}

// RuleCatalog enumerates every registered detection rule's ATT&CK mapping.
// Satisfied by *detection.Engine in production; isolated to an interface so
// admin tests don't need a full engine.
type RuleCatalog interface {
	Catalog() []RuleMetadata
}

// RuleMetadata is the minimal per-rule descriptor the Navigator-export
// endpoint needs. Mirrors detection.RuleMetadata; duplicated here so admin
// doesn't import detection (which would pull the whole engine into admin's
// build graph + tests).
type RuleMetadata struct {
	ID         string
	Techniques []string
}

// Handler serves the admin endpoints. Construct it with the enrollment + policy stores,
// the command inserter used to fan out policy pushes, and a slog logger.
type Handler struct {
	enrollments *enrollment.Store
	policy      *policy.Store
	commands    CommandInserter
	catalog     RuleCatalog
	logger      *slog.Logger
}

// New creates an admin handler. The handler does not perform its own auth — wrap it with
// authn.AdminToken at registration time.
//
// Panics if any required dependency is nil: enrollment Store for /enrollments routes,
// policy Store + CommandInserter for /policy. Fail-fast at construction mirrors the
// enrollment.NewHandler pattern — a misconfigured handler otherwise blows up only on the
// first request, after the server is already accepting connections.
//
// catalog may be nil; the ATT&CK coverage endpoint then returns an empty layer rather
// than 500, which makes unit tests of the legacy admin surface easier to write.
func New(es *enrollment.Store, ps *policy.Store, ci CommandInserter, catalog RuleCatalog, logger *slog.Logger) *Handler {
	if es == nil {
		panic("admin.New: enrollment store must not be nil")
	}
	if ps == nil {
		panic("admin.New: policy store must not be nil")
	}
	if ci == nil {
		panic("admin.New: command inserter must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{enrollments: es, policy: ps, commands: ci, catalog: catalog, logger: logger}
}

// RegisterRoutes wires the endpoints onto the mux. Callers wrap the returned handler in the
// admin-token middleware before mounting.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/enrollments", h.handleList)
	mux.HandleFunc("POST /api/v1/admin/enrollments/{host_id}/revoke", h.handleRevoke)
	mux.HandleFunc("GET /api/v1/admin/policy", h.handleGetPolicy)
	mux.HandleFunc("PUT /api/v1/admin/policy", h.handlePutPolicy)
	mux.HandleFunc("GET /api/v1/admin/attack-coverage", h.handleATTACKCoverage)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.enrollments.List(r.Context())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "admin list enrollments", "err", err)
		writeErr(r.Context(), h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(r.Context(), h.logger, w, http.StatusOK, rows)
}

type revokeRequest struct {
	Reason string `json:"reason"`
	Actor  string `json:"actor"`
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "missing host_id")
		return
	}

	var body revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	if body.Reason == "" || body.Actor == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "reason and actor are required")
		return
	}

	err := h.enrollments.Revoke(ctx, hostID, body.Reason, body.Actor)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "admin revoke", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	// Audit the revoke at WARN so it's visible in SigNoz alert queries. Span attributes give
	// SOC teams the query dimensions they expect (`edr.admin.action`, `edr.admin.actor`).
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "revoke"),
		attribute.String(attrkeys.AdminActor, body.Actor),
		attribute.String(attrkeys.HostID, hostID),
	)
	h.logger.WarnContext(ctx, "admin action",
		attrkeys.AdminAction, "revoke",
		attrkeys.AdminActor, body.Actor,
		attrkeys.AdminReason, body.Reason,
		attrkeys.HostID, hostID,
	)

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "admin encode response", "err", err)
	}
}

// writeErr serializes a typed error body through the same JSON+no-store headers as writeJSON,
// so admin responses are consistently application/json instead of text/plain. Callers pass a
// short `code` rather than a human sentence where possible.
func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	writeJSON(ctx, logger, w, status, map[string]string{"error": code})
}

// handleGetPolicy returns the current default policy. Used by the Phase 3 admin UI to
// render the blocklist editor form and by operators who want to confirm a pending edit
// before PUTting a new version.
func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := h.policy.Get(ctx, policy.DefaultName)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin get policy", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, p)
}

// putPolicyRequest is the body shape accepted by PUT /api/v1/admin/policy. `Actor` +
// `Reason` are required for audit. `Paths` + `Hashes` are optional individually but the
// effective blocklist must be one of those two forms; a completely empty PUT is still
// accepted so operators have a fast "clear everything" path.
type putPolicyRequest struct {
	Paths  []string `json:"paths"`
	Hashes []string `json:"hashes"`
	Actor  string   `json:"actor"`
	Reason string   `json:"reason"`
}

// handlePutPolicy is the end-to-end policy push: upsert the policy row, list active hosts,
// and queue a set_blocklist command for each. A non-zero fan-out failure count logs a
// warning but still reports 200 — the policy row is authoritative; the fan-out is best-
// effort and the next enroll/admin-push catches up any host whose command didn't land.
func (h *Handler) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 64 KiB is generous for a blocklist; if someone tries to push multi-MB the public
	// DoS vector is real. Same rationale as enrollment/handler.go's cap.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var body putPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	if body.Actor == "" || body.Reason == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "actor_reason_required")
		return
	}

	// List active hosts BEFORE committing the policy update. A listing failure after the
	// upsert would leave us with a committed v+1 row and a 500 response — the caller has
	// no way to know whether the policy landed, and retrying would bump the version again.
	// Moving the read ahead keeps the failure mode honest: a listing error aborts cleanly
	// and the DB is untouched.
	hostIDs, err := h.enrollments.ActiveHostIDs(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "admin put policy list hosts", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	p, err := h.policy.Update(ctx, policy.UpdateRequest{
		Name:   policy.DefaultName,
		Paths:  body.Paths,
		Hashes: body.Hashes,
		Actor:  body.Actor,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "admin put policy", "err", err)
		// Validation errors from policy.Update (non-absolute path, bad hash) should be a
		// 400 — the caller can fix their PUT body. Database / internal errors stay 500.
		status := http.StatusInternalServerError
		code := "internal"
		if isValidationError(err) {
			status = http.StatusBadRequest
			code = "invalid_blocklist"
		}
		writeErr(ctx, h.logger, w, status, code)
		return
	}

	// Fan out to every active host. Building the payload once and re-using is safe — the
	// store.Command.Payload field is json.RawMessage which is immutable once populated.
	payload, err := json.Marshal(policyCommandPayload{
		Name:    p.Name,
		Version: p.Version,
		Paths:   p.Blocklist.Paths,
		Hashes:  p.Blocklist.Hashes,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "admin put policy marshal payload", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	fanoutFailed := 0
	for _, hostID := range hostIDs {
		if _, err := h.commands.InsertCommand(ctx, store.Command{
			HostID:      hostID,
			CommandType: "set_blocklist",
			Payload:     payload,
		}); err != nil {
			fanoutFailed++
			h.logger.WarnContext(ctx, "admin put policy fan-out failed",
				attrkeys.HostID, hostID, "err", err)
		}
	}

	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "policy_update"),
		attribute.String(attrkeys.AdminActor, body.Actor),
		attribute.Int64("edr.policy.version", p.Version),
		attribute.Int("edr.policy.path_count", len(p.Blocklist.Paths)),
		attribute.Int("edr.policy.hash_count", len(p.Blocklist.Hashes)),
		attribute.Int("edr.policy.fanout_hosts", len(hostIDs)),
		attribute.Int("edr.policy.fanout_failed", fanoutFailed),
	)
	// Success is INFO. WARN is reserved for partial fan-out failures so operators can
	// actually tell a healthy policy push apart from one where N hosts missed the update.
	logFn := h.logger.InfoContext
	if fanoutFailed > 0 {
		logFn = h.logger.WarnContext
	}
	logFn(ctx, "admin policy updated",
		attrkeys.AdminAction, "policy_update",
		attrkeys.AdminActor, body.Actor,
		attrkeys.AdminReason, body.Reason,
		"edr.policy.version", p.Version,
		"edr.policy.path_count", len(p.Blocklist.Paths),
		"edr.policy.hash_count", len(p.Blocklist.Hashes),
		"edr.policy.fanout_hosts", len(hostIDs),
		"edr.policy.fanout_failed", fanoutFailed,
	)

	writeJSON(ctx, h.logger, w, http.StatusOK, p)
}

// policyCommandPayload is the wire shape of a set_blocklist command payload. Field names
// mirror what the agent's commander decodes and what the extension's PolicyStore expects.
type policyCommandPayload struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Paths   []string `json:"paths"`
	Hashes  []string `json:"hashes"`
}

// handleATTACKCoverage returns a MITRE ATT&CK Navigator layer document that
// enumerates the techniques covered by the registered detection rules. The
// output is dropped directly into https://mitre-attack.github.io/attack-navigator/
// to render as a heatmap on the matrix — one of the more reliable signals a
// security buyer asks for in an eval. Score is 1 for "any rule covers it",
// the list of covering rule IDs is in the technique's `comment`.
func (h *Handler) handleATTACKCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var catalog []RuleMetadata
	if h.catalog != nil {
		catalog = h.catalog.Catalog()
	}
	// technique -> rule IDs that cover it.
	coverage := make(map[string][]string)
	for _, rule := range catalog {
		for _, t := range rule.Techniques {
			coverage[t] = append(coverage[t], rule.ID)
		}
	}

	type navigatorTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Color       string `json:"color,omitempty"`
		Comment     string `json:"comment,omitempty"`
	}
	type navigatorLayer struct {
		Name        string               `json:"name"`
		Versions    map[string]string    `json:"versions"`
		Domain      string               `json:"domain"`
		Description string               `json:"description"`
		Techniques  []navigatorTechnique `json:"techniques"`
	}

	techniques := make([]navigatorTechnique, 0, len(coverage))
	for tid, rules := range coverage {
		techniques = append(techniques, navigatorTechnique{
			TechniqueID: tid,
			Score:       1,
			Color:       "#31a354",
			Comment:     "Covered by: " + strings.Join(rules, ", "),
		})
	}

	layer := navigatorLayer{
		Name:        "Fleet EDR coverage",
		Versions:    map[string]string{"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
		Domain:      "enterprise-attack",
		Description: "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules.",
		Techniques:  techniques,
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, layer)
}

// isValidationError reports whether err is a blocklist-shape violation returned by
// policy.Update (e.g. non-absolute path, bad hash). We key off the error string rather
// than a typed error because policy.Update already wraps the message and the alternative
// (exporting a sentinel per-error variant) would bloat the policy package for a single
// caller. The errors.Is check covers the common substring; if policy.Update grows more
// typed errors later, tighten this.
func isValidationError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "must be absolute") ||
		strings.Contains(s, "64 lowercase hex")
}
