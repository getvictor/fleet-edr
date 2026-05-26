package intake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// MaxIngestBodyBytes is the per-request body cap on POST /api/events. The contract is documented in openspec/specs/
// server-event-ingestion/spec.md (Body size limit requirement); see the comment on handleIngest for the enforcement shape.
// Exported for tests that need to compose right-at-cap and over-cap bodies without duplicating the magic number.
const MaxIngestBodyBytes = 10 * 1024 * 1024

// MaxIngestEventsPerRequest caps the number of events the parser accepts in a single batch. Closes the memory-amplification angle that the 10 MB body cap doesn't on its own: a minimal event JSON is ~50 bytes on the wire but the in-memory api.Event representation (json.RawMessage payload + the four string headers) is several hundred bytes — so a 10 MB body of microscopic events could expand to ~140k entries and ~60-80 MB of heap before the downstream InsertEvents loop runs. The agent's defaultBatchSize is 100; 10k is two orders of magnitude of headroom for legitimate batching while capping the blast radius of a hostile or buggy peer.
const MaxIngestEventsPerRequest = 10_000

// ParseAndValidateIngestBody is the parse + per-event validation half of POST /api/events, lifted out of handleIngest so the fuzz
// harness can drive it without a full HTTP server + Detection store. Returns (events, http.StatusOK, "") on success, or
// (nil, 4xx, errCode) on parse / validation failure. The error codes are the same stable set the HTTP handler emits:
// "invalid_json", "missing_fields_at_<i>", "host_id_mismatch", "too_many_events". The body-cap (413) check is upstream of
// this function (in readBodyWithCap); the store-insert (5xx) is downstream of it. The fuzz contract is therefore: every
// output MUST be one of {(200, ""), (400, "invalid_json"), (400, "missing_fields_at_<i>"), (400, "host_id_mismatch"),
// (400, "too_many_events")} - anything else is a finding.
//
// Streaming-decode shape (CodeRabbit #276 follow-up to #275): the previous shape called json.Unmarshal(body, &events) which
// fully materialises the []api.Event slice before len(events) is checked, so a 10 MB body of microscopic events still allocates
// ~140k api.Event structs (~60-80 MB of heap) before the MaxIngestEventsPerRequest cap fires. The fix is to decode incrementally
// with json.Decoder so the cap aborts the loop before the over-cap event is allocated. The per-event allocation still happens,
// but it's bounded to MaxIngestEventsPerRequest+1, not the entire body's worth.
func ParseAndValidateIngestBody(body []byte, pinnedHostID string) (events []api.Event, status int, errCode string) {
	dec := json.NewDecoder(bytes.NewReader(body))

	// Opening token must be `[`. Anything else (`{`, null, primitive, garbage, EOF) is invalid_json. This subsumes the
	// previous explicit nil-check on the literal `null` body: json.Decoder.Token() for `null` returns the nil Token, which
	// fails the json.Delim type-assert below, so the same input still returns invalid_json.
	tok, err := dec.Token()
	if err != nil {
		return nil, http.StatusBadRequest, "invalid_json"
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, http.StatusBadRequest, "invalid_json"
	}

	for i := 0; dec.More(); i++ {
		// Cap fires BEFORE the over-cap event is allocated. The +1 conceptual margin (we accept up to and including
		// MaxIngestEventsPerRequest events, then reject the (Max+1)th before decoding) keeps the heap-amplification path
		// closed even on a body whose byte count is at the 10 MB upstream cap.
		if i >= MaxIngestEventsPerRequest {
			return nil, http.StatusBadRequest, "too_many_events"
		}
		var e api.Event
		if err := dec.Decode(&e); err != nil {
			return nil, http.StatusBadRequest, "invalid_json"
		}
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			return nil, http.StatusBadRequest, "missing_fields_at_" + strconv.Itoa(i)
		}
		if e.HostID != pinnedHostID {
			return nil, http.StatusBadRequest, "host_id_mismatch"
		}
		events = append(events, e)
	}

	// Closing `]` must follow; anything else is malformed and surfaces as invalid_json. After the close, the decoder must
	// reach io.EOF on the next token call - trailing bytes after the array are also invalid_json. The two checks together
	// reject inputs like `[]extra` or `[][]` that json.Unmarshal would also reject.
	tok, err = dec.Token()
	if err != nil {
		return nil, http.StatusBadRequest, "invalid_json"
	}
	if delim, ok := tok.(json.Delim); !ok || delim != ']' {
		return nil, http.StatusBadRequest, "invalid_json"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, http.StatusBadRequest, "invalid_json"
	}

	return events, http.StatusOK, ""
}

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

	body, ok := h.readBodyWithCap(w, r)
	if !ok {
		return
	}

	events, status, errCode := ParseAndValidateIngestBody(body, pinnedHostID)
	if status != http.StatusOK {
		writeErr(ctx, h.logger, w, status, errCode)
		return
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

// readBodyWithCap enforces the per-request body cap in two stages and writes the appropriate error response if either
// stage rejects. Returns (body, true) on success or (nil, false) when the caller should return without further work.
// Split out of handleIngest so the latter stays under the cognitive-complexity budget (go:S3776).
//
//  1. Content-Length fast-path. If the client advertised a length beyond the cap, reject with HTTP 413 BEFORE
//     allocating any buffer. Cheap defense against a malicious or misconfigured caller that would otherwise trigger
//     a 100+ MB allocation per request.
//  2. Streaming enforce via http.MaxBytesReader. For chunked transfer-encoding (no Content-Length) or a lying
//     Content-Length, MaxBytesReader returns a typed *http.MaxBytesError once the cap is crossed mid-stream.
//     The previous shape used io.LimitReader, which silently truncates: a truncated body would then fail
//     json.Unmarshal and surface as `invalid_json`, hiding the real cause. MaxBytesReader's distinguished error is
//     what makes the 413-vs-400 split honest.
//
// HTTP 413 (RFC 9110 §15.5.14) is the canonical status; matches Elastic Fleet, Datadog, Splunk HEC, CrowdStrike.
func (h *Handler) readBodyWithCap(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ctx := r.Context()
	if r.ContentLength > MaxIngestBodyBytes {
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxIngestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, true
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	writeErr(ctx, h.logger, w, http.StatusBadRequest, "read_body")
	return nil, false
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
