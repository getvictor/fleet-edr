// Package ingest provides HTTP handlers for the EDR event ingestion API.
package ingest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	apiKey    string
	logger    *slog.Logger
	buildInfo BuildInfo
	startTime time.Time
}

// New creates an ingestion Handler. apiKey must not be empty; empty keys would accept every
// request, a demo-only behavior we refuse to ship. The store argument may be nil in tests that
// only exercise the ingest-auth path; readiness checks handle that case explicitly.
func New(s *store.Store, apiKey string, logger *slog.Logger, info BuildInfo) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if apiKey == "" {
		// Fail loud rather than silently accept every request. Production paths feed this from
		// config.Load which already enforces non-empty.
		panic("ingest.New: apiKey must not be empty")
	}
	return &Handler{
		store:     s,
		apiKey:    apiKey,
		logger:    logger,
		buildInfo: info,
		startTime: time.Now(),
	}
}

// RegisterRoutes registers the API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/events", h.handleIngest)
	mux.HandleFunc("GET /livez", h.handleLivez)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	// /health is an alias for /readyz, retained for human convenience and existing monitors.
	mux.HandleFunc("GET /health", h.handleReadyz)
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

	// Validate required fields.
	for i, e := range events {
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			http.Error(w, "event at index "+strconv.Itoa(i)+" missing required fields", http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()
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

func (h *Handler) authorize(r *http.Request) bool {
	// Belt-and-suspenders: New() panics on empty apiKey, but a zero-valued Handler constructed
	// outside of New (e.g., &Handler{} in a future refactor) would otherwise accept "Bearer ".
	if h.apiKey == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.apiKey)) == 1
}
