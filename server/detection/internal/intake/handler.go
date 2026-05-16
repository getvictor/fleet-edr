package intake

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// BuildInfo is injected at startup so the readiness endpoint
// advertises version + commit.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

// Handler serves the event ingestion API plus the
// livez/readyz/health endpoints.
type Handler struct {
	store     *mysql.Store
	logger    *slog.Logger
	buildInfo BuildInfo
	startTime time.Time
	metrics   api.MetricsRecorder
}

// New creates an ingestion Handler. The store argument may be nil in tests that only exercise the health endpoints; readiness checks
// handle that case explicitly.
func New(s *mysql.Store, logger *slog.Logger, info BuildInfo) *Handler {
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

// SetMetrics installs the OTel ingest-counter hook.
func (h *Handler) SetMetrics(m api.MetricsRecorder) { h.metrics = m }

// IngestHandler returns the POST /api/events handler. Callers wrap
// it in the endpoint context's HostToken middleware before mounting.
func (h *Handler) IngestHandler() http.Handler {
	return http.HandlerFunc(h.handleIngest)
}

// RegisterHealthRoutes registers the unauthenticated /livez,
// /readyz, /health routes.
func (h *Handler) RegisterHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", h.handleLivez)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	mux.HandleFunc("GET /health", h.handleReadyz)
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pinnedHostID, ok := endpointapi.HostIDFromContext(ctx)
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

	var events []api.Event
	if err := json.Unmarshal(body, &events); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_json")
		return
	}

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
	insertErr := h.store.InsertEvents(ctx, events)
	if h.metrics != nil {
		h.metrics.ObserveDBQuery(ctx, "insert_events", time.Since(insertStart))
	}
	if insertErr != nil {
		h.logger.ErrorContext(ctx, "insert error", "err", insertErr)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	if h.metrics != nil {
		h.metrics.EventsIngested(ctx, pinnedHostID, len(events))
	}

	upsertStart := time.Now()
	if err := h.store.UpsertHosts(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "upsert hosts", "err", err)
	}
	if h.metrics != nil {
		h.metrics.ObserveDBQuery(ctx, "upsert_hosts", time.Since(upsertStart))
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]int{"accepted": len(events)}); err != nil {
		h.logger.ErrorContext(ctx, "encode response", "err", err)
	}
}

type livezResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	BuildTime     string `json:"build_time,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

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
		h.logger.WarnContext(ctx, "readiness check: store is not configured")
		checks["db"] = checkResult{Status: "error", Error: "unavailable"}
		overall = "degraded"
		httpStatus = http.StatusServiceUnavailable
	} else {
		start := time.Now()
		if err := h.store.PingContext(pingCtx); err != nil {
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

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
