// Package ingest provides HTTP handlers for the EDR event ingestion API and the
// livez/readyz/health probes. Starting in Phase 1 the ingest endpoint itself is
// unauthenticated *at this layer*: the authn.HostToken middleware (wired up in main.go)
// resolves the bearer token to a host_id and pins it on the request context. This handler
// reads the pinned host_id via authn.HostIDFromContext and rejects any event payload whose
// HostID field does not match.
package ingest

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/store"
)

// BuildInfo is injected at startup so the readiness endpoint advertises version + commit.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

// MetricsHook is the tiny write surface for Phase 4 ingest metrics. Matches
// *metrics.Recorder; kept as an interface so tests don't need to import the OTel SDK.
// Nil is fine — instrumentation is optional.
type MetricsHook interface {
	EventsIngested(ctx context.Context, hostID string, n int)
	ObserveDBQuery(ctx context.Context, op string, d time.Duration)
}

// Handler serves the event ingestion API plus the livez/readyz/health endpoints.
type Handler struct {
	store     *store.Store
	logger    *slog.Logger
	buildInfo BuildInfo
	startTime time.Time
	metrics   MetricsHook
}

// New creates an ingestion Handler. The store argument may be nil in tests that only
// exercise the health endpoints; readiness checks handle that case explicitly.
func New(s *store.Store, logger *slog.Logger, info BuildInfo) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:     s,
		logger:    logger,
		buildInfo: info,
		startTime: time.Now(),
	}
}

// SetMetrics installs the Phase 4 ingest-counter hook. Safe to call after New.
func (h *Handler) SetMetrics(m MetricsHook) { h.metrics = m }

// IngestHandler returns the POST /api/v1/events handler. Callers wrap it in
// authn.HostToken middleware before mounting.
func (h *Handler) IngestHandler() http.Handler {
	return http.HandlerFunc(h.handleIngest)
}

// RegisterHealthRoutes registers the unauthenticated /livez, /readyz, /health routes.
// The ingest endpoint is mounted separately because it requires host-token middleware.
func (h *Handler) RegisterHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", h.handleLivez)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	// /health is an alias for /readyz, retained for human convenience and existing monitors.
	mux.HandleFunc("GET /health", h.handleReadyz)
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// authn.HostToken must have run ahead of us. If the pinned host_id is missing the
	// middleware wiring is broken — refuse rather than silently accept.
	pinnedHostID, ok := authn.HostIDFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, "ingest handler reached without host_id on context; middleware misconfigured")
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "read_body")
		return
	}

	var events []store.Event
	if err := json.Unmarshal(body, &events); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_json")
		return
	}

	// Validate required fields AND enforce host_id pinning: the token identifies ONE host,
	// so every event in the batch must carry that same host_id. This prevents a compromised
	// agent from impersonating another host by stuffing a different host_id in the payload.
	for i, e := range events {
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			writeErr(ctx, h.logger, w, http.StatusBadRequest, "missing_fields_at_"+strconv.Itoa(i))
			return
		}
		if e.HostID != pinnedHostID {
			writeErr(ctx, h.logger, w, http.StatusBadRequest, "host_id_mismatch")
			return
		}
	}

	insertStart := time.Now()
	if err := h.store.InsertEvents(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "insert error", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	if h.metrics != nil {
		h.metrics.ObserveDBQuery(ctx, "insert_events", time.Since(insertStart))
	}

	// Phase 4: count events successfully persisted. Labeled by host_id — the
	// authn-pinned value, not the per-event field (which we already validated matches
	// above), so a compromised agent cannot inflate another host's metric.
	if h.metrics != nil {
		h.metrics.EventsIngested(ctx, pinnedHostID, len(events))
	}

	// Update the hosts summary table with event counts and last-seen timestamps.
	upsertStart := time.Now()
	if err := h.store.UpsertHosts(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "upsert hosts", "err", err)
		// Non-fatal: events are already stored; host stats will be corrected on next server restart via backfill.
	}
	if h.metrics != nil {
		h.metrics.ObserveDBQuery(ctx, "upsert_hosts", time.Since(upsertStart))
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]int{"accepted": len(events)}); err != nil {
		h.logger.ErrorContext(ctx, "encode response", "err", err)
	}
}

// livezResponse is the liveness body; no dependency checks.
type livezResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	BuildTime     string `json:"build_time,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// readyzResponse is the readiness body; includes dependency checks.
type readyzResponse struct {
	Status        string                 `json:"status"`
	Version       string                 `json:"version,omitempty"`
	Commit        string                 `json:"commit,omitempty"`
	BuildTime     string                 `json:"build_time,omitempty"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
	Checks        map[string]checkResult `json:"checks"`
}

type checkResult struct {
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (h *Handler) handleLivez(w http.ResponseWriter, r *http.Request) {
	httpserver.NoStoreJSON(r.Context(), h.logger, w, http.StatusOK, livezResponse{
		Status:        "ok",
		Version:       h.buildInfo.Version,
		Commit:        h.buildInfo.Commit,
		BuildTime:     h.buildInfo.BuildTime,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
	})
}

func (h *Handler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	checks := map[string]checkResult{}
	overall := "ok"
	httpStatus := http.StatusOK

	if h.store == nil {
		// Defensive: tests (and potentially an /ingest-less build) can construct a Handler with a
		// nil store. Treat that as a readiness failure rather than panicking.
		h.logger.WarnContext(ctx, "readiness check: store is not configured")
		checks["db"] = checkResult{Status: "error", Error: "unavailable"}
		overall = "degraded"
		httpStatus = http.StatusServiceUnavailable
	} else {
		start := time.Now()
		if err := h.store.PingContext(pingCtx); err != nil {
			// Log the detailed error server-side so operators can diagnose, but return a generic
			// "unavailable" in the body — /readyz is unauthenticated and err.Error() can leak
			// DSN host names, driver details, and topology hints.
			h.logger.WarnContext(ctx, "readiness db ping failed", "err", err)
			checks["db"] = checkResult{Status: "error", Error: "unavailable"}
			overall = "degraded"
			httpStatus = http.StatusServiceUnavailable
		} else {
			checks["db"] = checkResult{Status: "ok", LatencyMS: time.Since(start).Milliseconds()}
		}
	}

	httpserver.NoStoreJSON(ctx, h.logger, w, httpStatus, readyzResponse{
		Status:        overall,
		Version:       h.buildInfo.Version,
		Commit:        h.buildInfo.Commit,
		BuildTime:     h.buildInfo.BuildTime,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
		Checks:        checks,
	})
}

// writeErr returns a typed application/json error body with the no-store headers httpserver.Build
// also applies to our success responses, so a 4xx/5xx from ingest is indistinguishable from other
// endpoints' errors on the wire. Callers pass short stable codes (e.g. "host_id_mismatch"), not
// human sentences, so client tooling can switch on them.
func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
