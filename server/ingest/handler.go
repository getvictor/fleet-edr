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

// Handler serves the event ingestion API plus the livez/readyz/health endpoints.
type Handler struct {
	store     *store.Store
	logger    *slog.Logger
	buildInfo BuildInfo
	startTime time.Time
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
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var events []store.Event
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields AND enforce host_id pinning: the token identifies ONE host,
	// so every event in the batch must carry that same host_id. This prevents a compromised
	// agent from impersonating another host by stuffing a different host_id in the payload.
	for i, e := range events {
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			http.Error(w, "event at index "+strconv.Itoa(i)+" missing required fields", http.StatusBadRequest)
			return
		}
		if e.HostID != pinnedHostID {
			http.Error(w, `{"error":"host_id_mismatch"}`, http.StatusBadRequest)
			return
		}
	}

	if err := h.store.InsertEvents(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "insert error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update the hosts summary table with event counts and last-seen timestamps.
	if err := h.store.UpsertHosts(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "upsert hosts", "err", err)
		// Non-fatal: events are already stored; host stats will be corrected on next server restart via backfill.
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
